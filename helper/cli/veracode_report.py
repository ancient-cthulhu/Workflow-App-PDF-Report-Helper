#!/usr/bin/env python3
"""Veracode consolidated PDF report.

Adds one pull-request comment carrying a PDF report built from the findings of
the SAST pipeline scan, the agent-based SCA scan and the IaC/Secrets scan.

Standalone: needs only veracode_findings.py and veracode_pdf.py alongside it,
standard library only, installs nothing at runtime. It reads scan output and
posts a comment; it does not gate or fail a build.

The three scans finish at different times, so no single job sees all three:

  export   Normalizes one scan's results into a fragment JSON, uploaded as
           artifact veracode-findings-<sha>-<scan>.
  build    Collects every fragment published for the same commit, its own plus
           any sibling already finished, and renders the combined PDF.
  comment  Upserts the sticky comment. Separate from build so the PDF artifact
           exists by the time its download link is resolved.

Each scan rebuilds the report, so the last to finish produces the full
three-scan document. Scans yet to report are shown as pending.

The GitHub REST API cannot attach a file to a comment, so the PDF is linked as
a workflow artifact, or with --publish-branch committed to a branch in the
scanned repo where the browser renders it inline.

Exit codes: 0 report produced or nothing to do, 1 could not be produced.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import os
import re
import sys
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import veracode_findings as vf
    import veracode_pdf as pdf
except ImportError as exc:
    print(f"::error::veracode_findings.py and veracode_pdf.py must sit next "
          f"to veracode_report.py ({exc}).")
    raise SystemExit(1)

FRAGMENT_SCHEMA = 1
MAX_FRAGMENT_BYTES = 64 * 1024 * 1024
SCAN_IDS = ["pipeline", "sca", "iac"]
SCAN_LABEL = {
    "pipeline": "Static Analysis (SAST)",
    "sca": "Software Composition Analysis (SCA)",
    "iac": "Infrastructure as Code & Secrets",
}
SCAN_SHORT = {"pipeline": "SAST", "sca": "SCA", "iac": "IaC/Secrets"}
SCAN_DEST = {scan: f"scan-{scan}" for scan in SCAN_IDS}
CONFIG_SECTION = {"pipeline": "veracode_static_scan",
                  "sca": "veracode_sca_scan",
                  "iac": "veracode_iac_secrets_scan"}
BANDS = ["critical", "high", "medium", "low", "info"]

NAVY = "#0F2E4A"
INK = "#1B2A38"
BODY = "#3A4A59"
MUTED = "#6B7A88"
LINK = "#0B5FA5"
HAIRLINE = "#DCE4EB"
PANEL = "#F4F7F9"

SEV_COLOR = {"critical": "#B3261E", "high": "#C25708", "medium": "#9A6B04",
             "low": "#1B6EC2", "info": "#6B7A88"}
SEV_TINT = {"critical": "#FCEDEB", "high": "#FDF1E8", "medium": "#FCF6E4",
            "low": "#EBF3FC", "info": "#F3F6F8"}
PASS_GREEN = "#1F7A4D"
PASS_TINT = "#E9F5EF"


def now_utc() -> _dt.datetime:
    """UTC now, honouring SOURCE_DATE_EPOCH for reproducible output."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.strip().isdigit():
        return _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc)
    return _dt.datetime.now(_dt.timezone.utc)


_HTML_TAG_RE = re.compile(
    r"</?(?:a|b|blockquote|br|code|div|em|h[1-6]|hr|i|img|li|ol|p|pre|small|"
    r"span|strong|sub|sup|table|tbody|td|th|thead|tr|u|ul)\b[^>]{0,400}>",
    re.IGNORECASE)


# Veracode remediation text ends with a link list ("References: <a>CWE</a>
# <a>OWASP</a>"). Once the anchors are stripped only the bare label words are
# left, which say nothing; the card's Reference row carries the real URL.
_TRAILING_REFS_RE = re.compile(
    r"\s*References?\s*:\s*[A-Za-z0-9 ,.\-()]{0,80}$", re.IGNORECASE)


def clean_detail(text: Optional[str], limit: int = 4000) -> str:
    return clean(_TRAILING_REFS_RE.sub("", clean(text, limit + 200)), limit)


def clean(text: Optional[str], limit: int = 4000) -> str:
    """Collapse whitespace and truncate. Text is display-only in the PDF."""
    import html as _html
    s = _HTML_TAG_RE.sub(" ", str(text or ""))
    s = _html.unescape(s)
    # Veracode marks up remediation text with real tags but backslash-escapes
    # angle brackets that are content, so a .NET closure field arrives as
    # \<\>4__this. Unescape after tag stripping to restore the identifier.
    s = s.replace("\\<", "<").replace("\\>", ">")
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "..."


def short_sha(sha: Optional[str]) -> str:
    s = (sha or "").strip()
    return s[:8] if len(s) > 8 else s


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _base_record(f: "vf.Finding") -> Dict[str, Any]:
    return {
        "category": f.category,
        "band": f.band,
        "rank": f.effective_rank,
        "cvss": f.cvss,
        "ident": f.ident,
        "cve": f.cve,
        "title": clean(f.title, 400),
        "location": clean(f.location, 300),
        "file": f.file,
        "line": f.line,
        "fix": clean(f.fix, 1200),
        "version": f.version,
        "ref_url": vf.safe_url(f.ref_url),
        "detail": clean_detail(f.detail, 1500),
        "function": clean(f.function, 160),
        "scope": clean(f.scope, 60),
        "detail_url": vf.safe_url(f.detail_url),
        "code": f.code,
        "native_id": f.native_id,
    }


def export_fragment(args: argparse.Namespace) -> int:
    """Normalize one scan's results into a fragment.

    Accepts several input files because the pipeline scan is matrixed over the
    packaged modules: a repo with a .NET and a JS module produces
    0-results.json and 1-results.json in separate artifacts. Reporting only one
    of them would drop every finding in the others, so all are parsed and
    merged.
    """
    mode = args.mode
    section = CONFIG_SECTION[mode]
    resolved = vf.resolve_threshold(
        [args.config] if args.config else [], section, args.threshold)
    try:
        threshold = vf.Threshold(resolved)
    except vf.FindingsError as exc:
        print(f"::warning::{exc} No fragment written for this scan.")
        return 0

    findings: List["vf.Finding"] = []
    report_url = ""
    advisories: List[Dict[str, str]] = []
    parsed_files = 0

    for path in args.input:
        if not os.path.exists(path):
            print(f"::warning::No results file at {path}.")
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        if not raw.strip():
            print(f"::warning::Results file {path} is empty.")
            continue
        try:
            batch = vf.load_findings(mode, raw, args.include_outdated)
        except vf.FindingsError as exc:
            # One unreadable module must not quietly shrink the report, so the
            # whole scan is abandoned rather than reported as partial.
            print(f"::warning::Could not parse {SCAN_SHORT[mode]} results from "
                  f"{path} ({exc}); no fragment written for this scan.")
            return 0
        findings.extend(batch)
        parsed_files += 1
        report_url = report_url or (vf.extract_report_url(raw) or "")
        if mode == "sca" and raw.lstrip()[:1] not in ("{", "["):
            try:
                advisories.extend(vf.parse_sca_update_advisor(raw))
            except Exception:  # noqa: BLE001
                pass
        print(f"  {os.path.basename(path)}: {len(batch)} finding(s)")

    if not parsed_files:
        print(f"::warning::No usable {SCAN_SHORT[mode]} results; nothing to "
              f"export.")
        return 0

    try:
        vf.correct_file_cases(findings)
    except Exception:  # noqa: BLE001 - link polish must never break the export
        pass

    if advisories:
        try:
            vf.backfill_advisor_in_use(advisories, findings)
        except Exception:  # noqa: BLE001
            advisories = []

    records = [_base_record(f) for f in findings]
    for rec, f in zip(records, findings):
        rec["gated"] = bool(threshold.gates(f))
        rec["url"] = vf.github_blob_url(f.file, f.line) or ""
        rec["ident_url"] = rec.get("ref_url") or vf.id_url(f.ident) or ""
        rec["url"] = vf.safe_url(rec["url"])

    advisories: List[Dict[str, str]] = []
    report_url = vf.extract_report_url(raw) or ""
    if mode == "sca" and raw.lstrip()[:1] not in ("{", "["):
        try:
            advisories = vf.parse_sca_update_advisor(raw)
            vf.backfill_advisor_in_use(advisories, findings)
        except Exception:
            advisories = []

    counts = {b: 0 for b in BANDS}
    for rec in records:
        counts[rec["band"]] += 1

    fragment = {
        "schema": FRAGMENT_SCHEMA,
        "scan": mode,
        "scan_label": SCAN_LABEL[mode],
        "threshold": threshold.raw,
        "generated_at": now_utc().isoformat(timespec="seconds"),
        "repo": env("SCAN_REPO"),
        "branch": env("BLOB_REF"),
        "sha": env("HEAD_SHA"),
        "pr_number": env("PR_NUMBER"),
        "run_url": env("RUN_URL"),
        "report_url": report_url,
        "server_url": env("GITHUB_SERVER_URL", "https://github.com"),
        "counts": counts,
        "total": len(records),
        "gated": sum(1 for r in records if r["gated"]),
        "advisories": advisories,
        "findings": records,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(fragment, fh, ensure_ascii=False)
    print(f"Exported {len(records)} {SCAN_SHORT[mode]} finding(s) from "
          f"{parsed_files} file(s) to {args.out} ({fragment['gated']} at or "
          f"above '{threshold.raw}').")
    return 0


def _api_get(url: str, token: str, accept: str = "application/vnd.github+json"):
    import urllib.request
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", accept)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=45) as resp:
        return resp.read()


def collect_fragments(dest_dir: str, sha: str, repo: str, token: str,
                      api: str) -> int:
    """Download fragments published by sibling scans for the same commit.

    Uses "List artifacts for a repository" filtered by artifact name, which
    needs only Actions: read on the integration repository. Best-effort: a
    failure just means the report covers fewer scans this run.
    """
    if not (sha and repo and token):
        print("::warning::Cannot collect sibling scan results "
              "(ARTIFACT_REPO/ARTIFACT_TOKEN/HEAD_SHA not all set); the report "
              "will cover only this scan.")
        return 0
    os.makedirs(dest_dir, exist_ok=True)
    found = 0
    for scan in SCAN_IDS:
        name = f"veracode-findings-{sha}-{scan}"
        url = (f"{api.rstrip('/')}/repos/{repo}/actions/artifacts"
               f"?name={name}&per_page=100")
        try:
            listing = json.loads(_api_get(url, token).decode("utf-8"))
        except Exception as exc:
            print(f"::warning::Could not list artifacts for {scan} ({exc}).")
            continue
        artifacts = [a for a in (listing.get("artifacts") or [])
                     if not a.get("expired")]
        if not artifacts:
            continue
        artifacts.sort(key=lambda a: a.get("created_at") or "", reverse=True)
        newest = artifacts[0]
        try:
            blob = _api_get(newest["archive_download_url"], token)
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                members = [m for m in zf.namelist() if m.endswith(".json")]
                if not members:
                    continue
                # Bound the inflated size before reading. A fragment is a few
                # hundred KB; anything near this cap is a decompression bomb,
                # not a scan result.
                info = zf.getinfo(members[0])
                if info.file_size > MAX_FRAGMENT_BYTES:
                    print(f"::warning::The {scan} fragment inflates to "
                          f"{info.file_size} bytes, which is implausible; "
                          f"skipping it.")
                    continue
                payload = zf.read(members[0])
        except Exception as exc:
            print(f"::warning::Could not download the {scan} fragment ({exc}).")
            continue
        target = os.path.join(dest_dir, f"collected-{scan}.json")
        with open(target, "wb") as fh:
            fh.write(payload)
        found += 1
    print(f"Collected {found} scan fragment(s) for commit {short_sha(sha)}.")
    return found


def load_fragments(directory: str) -> Dict[str, Dict[str, Any]]:
    """Newest valid fragment per scan id, from every JSON file in `directory`."""
    out: Dict[str, Dict[str, Any]] = {}
    if not os.path.isdir(directory):
        return out
    for root, _dirs, files in os.walk(directory):
        for fname in sorted(files):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    frag = json.load(fh)
            except (ValueError, OSError) as exc:
                print(f"::warning::Ignoring unreadable fragment {path} ({exc}).")
                continue
            scan = frag.get("scan")
            if scan not in SCAN_IDS or not isinstance(frag.get("findings"), list):
                continue
            prev = out.get(scan)
            if prev is None or str(frag.get("generated_at", "")) >= str(
                    prev.get("generated_at", "")):
                out[scan] = frag
    return out


CATEGORY_ORDER = ["Flaw", "Vulnerability", "Misconfiguration", "Secret",
                  "Outdated Library"]
CATEGORY_LABEL = {
    "Flaw": "Static analysis flaws",
    "Vulnerability": "Vulnerable dependencies",
    "Misconfiguration": "Infrastructure misconfigurations",
    "Secret": "Exposed secrets",
    "Outdated Library": "Outdated libraries",
}


class ReportContext:
    """Everything the renderer needs that is not a finding."""

    def __init__(self, fragments: Dict[str, Dict[str, Any]]) -> None:
        self.fragments = fragments
        any_frag = next(iter(fragments.values()), {})
        self.repo = env("SCAN_REPO") or any_frag.get("repo", "")
        self.branch = env("BLOB_REF") or any_frag.get("branch", "")
        self.sha = env("HEAD_SHA") or any_frag.get("sha", "")
        self.pr = env("PR_NUMBER") or any_frag.get("pr_number", "")
        self.server = (env("GITHUB_SERVER_URL")
                       or any_frag.get("server_url") or "https://github.com")
        self.generated = now_utc()
        self.missing = [s for s in SCAN_IDS if s not in fragments]

    @property
    def all_findings(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for scan in SCAN_IDS:
            frag = self.fragments.get(scan)
            if not frag:
                continue
            for rec in frag["findings"]:
                rec = dict(rec)
                rec["scan"] = scan
                out.append(rec)
        return out

    def totals(self) -> Dict[str, int]:
        counts = {b: 0 for b in BANDS}
        for frag in self.fragments.values():
            for band in BANDS:
                counts[band] += int((frag.get("counts") or {}).get(band, 0))
        return counts

    @property
    def complete(self) -> bool:
        """True only when every scan has reported for this commit."""
        return not self.missing

    @property
    def gated_total(self) -> int:
        return sum(int(frag.get("gated") or 0)
                   for frag in self.fragments.values())

    @property
    def finding_total(self) -> int:
        return sum(int(frag.get("total") or 0)
                   for frag in self.fragments.values())


def _sev_label(rec: Dict[str, Any]) -> str:
    band = rec.get("band", "info")
    label = band.upper()
    cvss = rec.get("cvss")
    if cvss not in (None, ""):
        try:
            label += f"  {float(cvss):g}"
        except (TypeError, ValueError):
            pass
    return label


def _sort_key(rec: Dict[str, Any]) -> Tuple[int, int, str, str]:
    return (-int(rec.get("rank", 0)),
            0 if rec.get("gated") else 1,
            rec.get("file", "") or rec.get("location", ""),
            rec.get("title", ""))


def _page_furniture(ctx: ReportContext):
    """Return an on_page callback painting the running header and footer."""
    subtitle = ctx.repo or "Veracode scan"

    def paint(canvas: pdf.Canvas, index: int) -> None:
        if index == 0:
            return
        canvas.rect(0, 0, canvas.width, 30, fill=NAVY)
        canvas.text(46, 11, "Veracode Security Report", "b", 8.5, "#FFFFFF")
        label = subtitle + (f"  ·  {short_sha(ctx.sha)}" if ctx.sha else "")
        w = pdf.text_width(label, "r", 8)
        canvas.text(canvas.width - 46 - w, 11.5, label, "r", 8, "#AFC3D4")
        foot_y = canvas.height - 32
        canvas.line(46, foot_y, canvas.width - 46, foot_y, HAIRLINE, 0.6)
        canvas.text(46, foot_y + 7,
                    "Generated by the Veracode GitHub workflow integration",
                    "r", 7.2, MUTED)
        num = f"Page {index + 1}"
        w = pdf.text_width(num, "r", 7.2)
        canvas.text(canvas.width - 46 - w, foot_y + 7, num, "r", 7.2, MUTED)

    return paint


def _stat_boxes(doc: pdf.Doc, counts: Dict[str, int]) -> None:
    gap = 8.0
    n = len(BANDS)
    w = (doc.content_width - gap * (n - 1)) / n
    h = 46.0
    doc.ensure(h + 6)
    x = doc.ml
    for band in BANDS:
        color = SEV_COLOR[band]
        doc.c.rect(x, doc.y, w, h, fill=SEV_TINT[band], radius=3)
        doc.c.rect(x, doc.y, 3.0, h, fill=color)
        value = str(counts.get(band, 0))
        doc.c.text(x + 12, doc.y + 9, value, "b", 20, color)
        doc.c.text(x + 12, doc.y + 32, band.upper(), "b", 7.2, MUTED)
        x += w + gap
    doc.y += h + 6


def _verdict_banner(doc: pdf.Doc, ctx: ReportContext) -> None:
    failed = ctx.gated_total > 0
    partial = not ctx.complete
    if failed:
        color, tint = SEV_COLOR["critical"], SEV_TINT["critical"]
        headline = "REVIEW RECOMMENDED"
        detail = (f"{ctx.gated_total} of {ctx.finding_total} finding(s) meet or "
                  f"exceed the configured severity threshold. They are listed "
                  f"in priority order below.")
    elif partial:
        # Never present incomplete coverage as an all-clear.
        color, tint = SEV_COLOR["medium"], SEV_TINT["medium"]
        headline = "INCOMPLETE COVERAGE"
        reported = len(SCAN_IDS) - len(ctx.missing)
        detail = (f"Only {reported} of {len(SCAN_IDS)} scans have reported for "
                  f"this commit, and nothing they found meets the configured "
                  f"threshold. This is not an all-clear: "
                  f"{', '.join(SCAN_SHORT[s] for s in ctx.missing)} has not "
                  f"reported.")
    else:
        color, tint = PASS_GREEN, PASS_TINT
        headline = "NOTHING AT OR ABOVE THRESHOLD"
        detail = (f"All three scans reported. {ctx.finding_total} finding(s) "
                  f"in total, none of which meet the configured threshold.")
    lines = pdf.wrap_text(detail, "r", 8.6, doc.content_width - 34)
    h = 26 + len(lines) * 12 + 8
    doc.ensure(h + 8)
    doc.c.rect(doc.ml, doc.y, doc.content_width, h, fill=tint, radius=3)
    doc.c.rect(doc.ml, doc.y, 4.0, h, fill=color)
    doc.c.text(doc.ml + 16, doc.y + 11, headline, "b", 11.5, color)
    y = doc.y + 30
    for line in lines:
        doc.c.text(doc.ml + 16, y, line, "r", 8.6, BODY)
        y += 12
    doc.y += h + 12


def _meta_grid(doc: pdf.Doc, ctx: ReportContext) -> None:
    scans = ", ".join(SCAN_SHORT[s] for s in SCAN_IDS if s in ctx.fragments)
    items = [
        ("Repository", ctx.repo or "unknown"),
        ("Branch", ctx.branch or "unknown"),
        ("Commit", short_sha(ctx.sha) or "unknown"),
        ("Pull request", f"#{ctx.pr}" if ctx.pr else "not a pull request"),
        ("Scans included", scans or "none"),
        ("Generated", ctx.generated.strftime("%d %b %Y %H:%M UTC")),
    ]
    col_w = doc.content_width / 3.0
    rows = [items[i:i + 3] for i in range(0, len(items), 3)]
    h = len(rows) * 30 + 12
    doc.ensure(h)
    doc.c.rect(doc.ml, doc.y, doc.content_width, h, fill=PANEL, radius=3)
    y = doc.y + 8
    for row in rows:
        x = doc.ml + 14
        for label, value in row:
            doc.c.text(x, y, label.upper(), "b", 6.8, MUTED)
            doc.c.text(x, y + 11,
                       pdf.wrap_text(value, "b", 9, col_w - 20)[0], "b", 9, INK)
            x += col_w
        y += 30
    doc.y += h + 14


def _coverage_table(doc: pdf.Doc, ctx: ReportContext) -> None:
    cols = [pdf.Column("Scan", 2.6), pdf.Column("Status", 1.5),
            pdf.Column("Threshold", 1.2, align="c"),
            pdf.Column("Findings", 1.0, align="c"),
            pdf.Column("At/above", 1.0, align="c"),
            pdf.Column("Crit", 0.75, align="c"),
            pdf.Column("High", 0.75, align="c"),
            pdf.Column("Med", 0.75, align="c"),
            pdf.Column("Low", 0.75, align="c"),
            pdf.Column("Info", 0.75, align="c")]
    rows = []
    for scan in SCAN_IDS:
        frag = ctx.fragments.get(scan)
        if not frag:
            rows.append([{"text": SCAN_LABEL[scan], "color": LINK,
                          "dest": SCAN_DEST[scan]},
                         {"text": "Not reported", "color": MUTED,
                          "font": "i"},
                         "-", "-", "-", "-", "-", "-", "-", "-"])
            continue
        gated = int(frag.get("gated") or 0)
        counts = frag.get("counts") or {}
        status = f"{gated} to review" if gated else "Clear"
        if frag.get("summary_only"):
            status += " *"
        rows.append([
            {"text": SCAN_LABEL[scan], "color": LINK,
             "dest": SCAN_DEST[scan]},
            {"text": status, "font": "b",
             "color": SEV_COLOR["critical"] if gated else PASS_GREEN},
            str(frag.get("threshold", "-")),
            str(frag.get("total", 0)),
            {"text": str(gated), "font": "b",
             "color": SEV_COLOR["critical"] if gated else BODY},
            *[str(counts.get(b, 0)) for b in BANDS],
        ])
    pdf.draw_table(doc, cols, rows, header_fill=NAVY)


def _top_risks(doc: pdf.Doc, ctx: ReportContext, limit: int = 8) -> None:
    """Priority list on the summary page, sized to whatever room is left.

    Measured before the heading is drawn so the block is either shown whole on
    the summary page or left out entirely. A heading followed by one orphaned
    row on the next page reads worse than no block at all, and every finding
    appears in full detail later regardless.
    """
    ranked = sorted(ctx.all_findings, key=_sort_key)[:limit]
    if not ranked:
        return
    cols = [pdf.Column("Severity", 1.5), pdf.Column("Scan", 1.35),
            pdf.Column("Identifier", 2.0), pdf.Column("Finding", 4.0),
            pdf.Column("Location", 2.6)]
    rows = []
    for rec in ranked:
        band = rec.get("band", "info")
        rows.append([
            {"text": _sev_label(rec), "font": "b", "size": 7.8,
             "color": SEV_COLOR[band]},
            SCAN_SHORT.get(rec.get("scan", ""), ""),
            {"text": rec.get("ident") or "-", "font": "m", "size": 7.4,
             "url": rec.get("ident_url") or ""},
            clean(rec.get("title"), 180),
            {"text": _location_text(rec), "font": "m", "size": 7.4,
             "color": LINK if rec.get("url") else BODY,
             "url": rec.get("url") or ""},
        ])

    heading_h = 46.0
    fits = pdf.fit_rows(doc, cols, rows, doc.space_left - heading_h)
    if fits < 3:
        return
    rows = rows[:fits]

    doc.heading("Where to start", size=11.5, top_gap=6, rule=False,
                bottom_gap=2)
    doc.paragraph(
        f"The {len(rows)} highest-severity findings across all three scans, in "
        f"priority order. Full detail for every finding follows.",
        size=8.4, color=MUTED, bottom_gap=8)
    pdf.draw_table(doc, cols, rows, header_fill=NAVY)


def _location_text(rec: Dict[str, Any]) -> str:
    if rec.get("file"):
        loc = rec["file"]
        if rec.get("line"):
            loc += f":{rec['line']}"
        return loc
    return rec.get("location") or "-"


# Paths, URLs and source lines read better monospaced. Measurement and drawing
# must agree on this or Courier's wider glyphs overflow the card.
_MONO_ROWS = ("Location", "Reference", "Source")


def _row_font(label: str) -> str:
    return "m" if label in _MONO_ROWS else "r"


def _finding_card(doc: pdf.Doc, rec: Dict[str, Any], number: int) -> None:
    """One finding rendered as a bordered card with a severity accent bar."""
    band = rec.get("band", "info")
    color = SEV_COLOR[band]
    pad = 12.0
    inner = doc.content_width - pad * 2 - 6.0
    title = clean(rec.get("title"), 400) or rec.get("ident") or "Finding"

    rows: List[Tuple[str, str, str]] = []
    package = ""
    if rec.get("category") in ("Vulnerability", "Outdated Library"):
        package = " ".join(x for x in (rec.get("location"),
                                       rec.get("version")) if x).strip()

    location = _location_text(rec)
    if location != "-" and not (package and not rec.get("file")):
        rows.append(("Location", location, rec.get("url") or ""))
    if rec.get("function"):
        rows.append(("Function", rec["function"], ""))
    if rec.get("code"):
        rows.append(("Source", rec["code"], ""))
    if package:
        rows.append(("Package", package, ""))
    if rec.get("cve") and rec.get("cve") != rec.get("ident"):
        rows.append(("Related CVE", rec["cve"], vf.id_url(rec["cve"]) or ""))
    if rec.get("fix"):
        label = ("Fixed in" if rec.get("category") == "Vulnerability"
                 else "Remediation")
        rows.append((label, clean(rec["fix"], 900), ""))
    scope = rec.get("scope") or ""
    if scope and not (rec.get("function") or "").startswith(scope):
        rows.append(("Scope", scope, ""))
    detail = clean(rec.get("detail"), 1200)
    if detail and detail.rstrip(".") != title.rstrip("."):
        rows.append(("Details", detail, ""))
    if rec.get("detail_url"):
        rows.append(("Reference", rec["detail_url"], rec["detail_url"]))
    elif rec.get("ref_url"):
        rows.append(("Reference", rec["ref_url"], rec["ref_url"]))

    label_w = 62.0
    value_w = inner - label_w
    title_lines = pdf.wrap_text(title, "b", 10, inner - 4)
    row_lines = [pdf.wrap_text(v, _row_font(lbl), 8.2, value_w)
                 for lbl, v, _u in rows]
    height = (10 + 15 + len(title_lines) * 12.6 + 6
              + sum(len(ls) * 11.4 + 3 for ls in row_lines) + 8)

    max_h = doc.bottom - doc.mt
    if height > max_h:
        while row_lines and height > max_h:
            longest = max(range(len(row_lines)), key=lambda i: len(row_lines[i]))
            drop = row_lines[longest]
            keep = max(1, len(drop) - 4)
            height -= (len(drop) - keep) * 11.4
            row_lines[longest] = drop[:keep]
            if len(drop) == keep:
                break
    doc.ensure(height)

    top = doc.y
    doc.c.rect(doc.ml, top, doc.content_width, height, fill="#FFFFFF",
               stroke=HAIRLINE, line_width=0.7, radius=3)
    doc.c.rect(doc.ml, top, 3.5, height, fill=color)

    x = doc.ml + 6.0 + pad
    y = top + 10
    chip_w = doc.chip(x, y, _sev_label(rec), color, size=7.0, height=13)
    ident = rec.get("ident") or ""
    if ident:
        ix = x + chip_w + 8
        doc.c.text(ix, y + 2.4, ident, "m", 8.2,
                   LINK if rec.get("ident_url") else INK)
        if rec.get("ident_url"):
            doc.c.link(ix, y, pdf.text_width(ident, "m", 8.2), 12,
                       rec["ident_url"])
    tag = f"#{number}"
    doc.c.text(doc.ml + doc.content_width - pad - pdf.text_width(tag, "b", 7.5),
               y + 3, tag, "b", 7.5, MUTED)

    y += 15 + 6
    for line in title_lines:
        doc.c.text(x, y, line, "b", 10, INK)
        y += 12.6
    y += 6

    for (label, _value, url), lines in zip(rows, row_lines):
        doc.c.text(x, y + 0.6, label, "b", 7.4, MUTED)
        font = _row_font(label)
        ly = y
        for line in lines:
            doc.c.text(x + label_w, ly, line, font, 8.2,
                       LINK if url else BODY)
            ly += 11.4
        if url:
            doc.c.link(x + label_w, y, value_w, len(lines) * 11.4, url)
        y = ly + 3

    doc.y = top + height + 8


def _overflow_table(doc: pdf.Doc, records: Sequence[Dict[str, Any]]) -> None:
    cols = [pdf.Column("Severity", 1.2), pdf.Column("Identifier", 1.7),
            pdf.Column("Finding", 4.4), pdf.Column("Location", 2.9)]
    rows = []
    for rec in records:
        band = rec.get("band", "info")
        rows.append([
            {"text": _sev_label(rec), "font": "b", "color": SEV_COLOR[band]},
            {"text": rec.get("ident") or "-", "font": "m", "size": 7.5,
             "url": rec.get("ident_url") or ""},
            clean(rec.get("title"), 200),
            {"text": _location_text(rec), "font": "m", "size": 7.3,
             "color": LINK if rec.get("url") else BODY,
             "url": rec.get("url") or ""},
        ])
    pdf.draw_table(doc, cols, rows, header_fill="#4A5C6D")


def _advisor_table(doc: pdf.Doc, advisories: Sequence[Dict[str, str]]) -> None:
    if not advisories:
        return
    doc.heading("Update advisor", size=11, top_gap=14, rule=False,
                bottom_gap=2, bookmark_level=1)
    doc.paragraph("Safe versions that resolve one or more of the "
                  "vulnerabilities above.", size=8.4, color=MUTED,
                  bottom_gap=8)
    spec = [("library", "Library"), ("in_use", "In use"),
            ("update_to", "Update to"), ("fixes", "Fixes"),
            ("breaking", "Breaking change")]
    keys = [(k, lbl) for k, lbl in spec
            if k == "library" or any(a.get(k) for a in advisories)]
    weights = {"library": 3.0, "in_use": 1.4, "update_to": 1.4,
               "fixes": 1.2, "breaking": 1.6}
    cols = [pdf.Column(lbl, weights.get(k, 1.5),
                       align="c" if k != "library" else "l")
            for k, lbl in keys]
    rows = [[{"text": a.get(k, "") or "-",
              "font": "m" if k in ("in_use", "update_to") else "r",
              "size": 7.8 if k in ("in_use", "update_to") else 8.2}
             for k, _lbl in keys] for a in advisories]
    pdf.draw_table(doc, cols, rows, header_fill="#4A5C6D")


def _scan_section(doc: pdf.Doc, ctx: ReportContext, scan: str,
                  max_cards: int) -> None:
    frag = ctx.fragments.get(scan)
    doc.heading(SCAN_LABEL[scan], size=15, bookmark_level=0, top_gap=20)
    doc.c.dest(SCAN_DEST[scan], doc.y - 40)

    if not frag:
        doc.paragraph(
            f"This scan did not report results for commit "
            f"{short_sha(ctx.sha) or 'this commit'}. It may still be running, "
            f"may be disabled for this repository, or may have failed before "
            f"producing findings. The report is regenerated by each scan as it "
            f"finishes, so a later run of this comment will include it.",
            font="i", color=MUTED)
        return

    gated = int(frag.get("gated") or 0)
    total = int(frag.get("total") or 0)
    verdict = ("Review" if gated else "Clear")
    vcolor = SEV_COLOR["critical"] if gated else PASS_GREEN
    doc.ensure(20)
    w = doc.chip(doc.ml, doc.y, verdict.upper(), vcolor, size=7.2, height=13)
    doc.c.text(doc.ml + w + 9, doc.y + 2.6,
               f"{total} finding(s) · {gated} at or above threshold "
               f"'{frag.get('threshold', '?')}'", "r", 8.6, BODY)
    doc.y += 22

    if frag.get("report_url"):
        doc.ensure(14)
        label = "Full results on the Veracode platform"
        doc.c.text(doc.ml, doc.y, label, "r", 8.4, LINK)
        doc.c.link(doc.ml, doc.y, pdf.text_width(label, "r", 8.4), 11,
                   frag["report_url"])
        doc.y += 16

    if frag.get("summary_only"):
        doc.paragraph(
            "These totals were reported by this scan's own run and carried "
            "forward. The individual findings are not available in this "
            "document; open that scan's report for the detail.",
            font="i", color=MUTED)
        return

    records = sorted(frag["findings"], key=_sort_key)
    if not records:
        doc.paragraph("No findings were reported by this scan.", font="i",
                      color=MUTED)
        _advisor_table(doc, frag.get("advisories") or [])
        return

    shown = 0
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        by_cat.setdefault(rec.get("category", "Other"), []).append(rec)
    ordered = ([(c, by_cat.pop(c)) for c in CATEGORY_ORDER if c in by_cat]
               + sorted(by_cat.items()))

    for category, items in ordered:
        label = CATEGORY_LABEL.get(category, category)
        doc.heading(f"{label} ({len(items)})", size=11, top_gap=14,
                    rule=False, bottom_gap=6, bookmark_level=1)
        overflow: List[Dict[str, Any]] = []
        for rec in items:
            if shown >= max_cards:
                overflow.append(rec)
                continue
            shown += 1
            _finding_card(doc, rec, shown)
        if overflow:
            doc.paragraph(
                f"{len(overflow)} further finding(s) in this category are "
                f"listed in summary form to keep the report a usable length.",
                font="i", size=8.2, color=MUTED, bottom_gap=6)
            _overflow_table(doc, overflow)

    _advisor_table(doc, frag.get("advisories") or [])


def _appendix(doc: pdf.Doc, ctx: ReportContext) -> None:
    doc.heading("Appendix", size=15, bookmark_level=0, top_gap=22)
    doc.heading("Severity model", size=11, top_gap=6, rule=False,
                bottom_gap=6, bookmark_level=1)
    doc.paragraph(
        "Every finding is ranked on the higher of its reported severity label "
        "and the band derived from its CVSS base score, so a finding labelled "
        "Unknown that carries a high score is not under-rated. A finding with "
        "no usable severity signal is floored rather than treated as "
        "informational: exposed secrets floor to High, everything else to "
        "Medium.", size=8.5, bottom_gap=10)
    cols = [pdf.Column("Band", 1.2), pdf.Column("CVSS base score", 1.6),
            pdf.Column("Interpretation", 5.0)]
    rows = [
        [{"text": "Critical", "font": "b", "color": SEV_COLOR["critical"]},
         "9.0 - 10.0", "Exploitable with severe impact. Fix before merging."],
        [{"text": "High", "font": "b", "color": SEV_COLOR["high"]},
         "7.0 - 8.9", "Significant risk. Fix in this change where practical."],
        [{"text": "Medium", "font": "b", "color": SEV_COLOR["medium"]},
         "4.0 - 6.9", "Moderate risk. Schedule remediation."],
        [{"text": "Low", "font": "b", "color": SEV_COLOR["low"]},
         "0.1 - 3.9", "Limited risk. Address opportunistically."],
        [{"text": "Info", "font": "b", "color": SEV_COLOR["info"]},
         "0.0 or none", "No direct risk. Provided for awareness."],
    ]
    pdf.draw_table(doc, cols, rows, header_fill="#4A5C6D")

    doc.heading("Thresholds applied", size=11, top_gap=14, rule=False,
                bottom_gap=6, bookmark_level=1)
    doc.paragraph(
        "A finding at or above its scan's threshold is counted as needing "
        "review on the summary page. Thresholds are set per scan when the "
        "report runs and default to medium. They order the work in this "
        "report and do not gate a build.", size=8.5, bottom_gap=10)
    cols = [pdf.Column("Scan", 3.4), pdf.Column("Threshold", 1.6, align="c"),
            pdf.Column("Findings at or above it", 2.4, align="c")]
    rows = []
    for scan in SCAN_IDS:
        frag = ctx.fragments.get(scan) or {}
        rows.append([
            SCAN_LABEL[scan],
            str(frag.get("threshold", "not reported")),
            str(frag.get("gated", "-")) if frag else "-"])
    pdf.draw_table(doc, cols, rows, header_fill="#4A5C6D")

    doc.heading("About this report", size=11, top_gap=14, rule=False,
                bottom_gap=6, bookmark_level=1)
    doc.paragraph(
        "Produced by the Veracode GitHub workflow integration from the results "
        "of the pipeline SAST scan, the agent-based SCA scan and the "
        "IaC/Secrets scan for this commit. Identifiers and file locations link "
        "back to the source in GitHub and to the relevant CWE, CVE or advisory "
        "record. Findings are point-in-time and reflect only what these three "
        "scans observed; they are not a statement that no other issue exists.",
        size=8.5, bottom_gap=10)
    for frag in (ctx.fragments.get(s) for s in SCAN_IDS):
        if frag and frag.get("run_url"):
            label = "Workflow run that produced this report"
            doc.ensure(14)
            doc.c.text(doc.ml, doc.y, label, "r", 8.4, LINK)
            doc.c.link(doc.ml, doc.y, pdf.text_width(label, "r", 8.4), 11,
                       frag["run_url"])
            doc.y += 16
            break


def _cover(doc: pdf.Doc, ctx: ReportContext) -> None:
    canvas = doc.c
    band_h = 104.0
    canvas.rect(0, 0, canvas.width, band_h, fill=NAVY)
    canvas.rect(0, band_h - 4, canvas.width, 4, fill="#00A3E0")
    canvas.text(46, 30, "VERACODE", "b", 10, "#7FC9E8", char_space=2.4)
    canvas.text(46, 48, "Security Scan Report", "b", 22, "#FFFFFF")
    sub = ctx.repo or "Repository"
    if ctx.branch:
        sub += f"  ·  {ctx.branch}"
    canvas.text(46, 78, sub, "r", 10, "#AFC3D4")
    doc.y = band_h + 22
    canvas.bookmark("Executive summary", 0, doc.y - 16)

    _meta_grid(doc, ctx)
    _verdict_banner(doc, ctx)

    doc.heading("Findings by severity", size=11.5, top_gap=2, rule=False,
                bottom_gap=8)
    _stat_boxes(doc, ctx.totals())

    doc.heading("Scan coverage", size=11.5, top_gap=12, rule=False,
                bottom_gap=8)
    doc.paragraph("Select a scan name to jump to its findings.", size=8.2,
                  color=MUTED, bottom_gap=6)
    _coverage_table(doc, ctx)

    if ctx.missing:
        names = ", ".join(SCAN_SHORT[s] for s in ctx.missing)
        doc.paragraph(
            f"Not every scan has reported for this commit ({names} missing). "
            f"The report is rebuilt by each scan as it completes, so the "
            f"linked document is replaced when the remaining scans finish.",
            font="i", size=8.3, color=MUTED, bottom_gap=10)

    _top_risks(doc, ctx)


def render_pdf(ctx: ReportContext, out_path: str, page_size: str = "a4",
               max_cards: int = 250) -> str:
    canvas = pdf.Canvas(
        page_size,
        title=f"Veracode Security Report - {ctx.repo or 'repository'}",
        author="Veracode GitHub workflow integration",
        subject=f"SAST, SCA and IaC/Secrets findings for "
                f"{ctx.repo}@{short_sha(ctx.sha)}",
        creation_date=ctx.generated.strftime("D:%Y%m%d%H%M%S+00'00'"))
    doc = pdf.Doc(canvas, margin_top=58, margin_bottom=48,
                  on_page=_page_furniture(ctx))
    doc.y = 0
    _cover(doc, ctx)
    for scan in SCAN_IDS:
        doc.page_break()
        _scan_section(doc, ctx, scan, max_cards)
    doc.page_break()
    _appendix(doc, ctx)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                exist_ok=True)
    canvas.save(out_path)
    return out_path


def artifact_deep_link(server: str, repo: str, run_id: str, name: str,
                       token: str, api: str) -> str:
    """Deep link to a named artifact in this run, falling back to the run page."""
    if not (repo and run_id):
        return ""
    run_page = f"{server.rstrip('/')}/{repo}/actions/runs/{run_id}"
    if not token:
        return run_page
    try:
        url = (f"{api.rstrip('/')}/repos/{repo}/actions/runs/{run_id}"
               f"/artifacts?per_page=100")
        data = json.loads(_api_get(url, token).decode("utf-8"))
        for art in data.get("artifacts") or []:
            if art.get("name") == name and not art.get("expired"):
                return f"{run_page}/artifacts/{art['id']}"
    except Exception:
        pass
    return run_page


def publish_to_branch(path: str, branch: str, repo: str, token: str,
                      api: str, sha: str, server: str) -> str:
    """Commit the PDF to `branch` in the scanned repo and return its blob URL.

    Opt-in. The branch holds security findings for anyone with repository read
    access and is never pruned automatically, so enable it only where that is
    acceptable. Requires Contents: write on the dispatch token; on any failure
    the caller falls back to the artifact link.
    """
    import base64
    import urllib.error
    import urllib.request

    def req(method: str, url: str, payload: Optional[dict] = None):
        body = json.dumps(payload).encode() if payload is not None else None
        r = urllib.request.Request(url, data=body, method=method)
        r.add_header("Authorization", f"Bearer {token}")
        r.add_header("Accept", "application/vnd.github+json")
        r.add_header("X-GitHub-Api-Version", "2022-11-28")
        if body is not None:
            r.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(r, timeout=45) as resp:
            return json.loads(resp.read().decode("utf-8") or "null")

    base = f"{api.rstrip('/')}/repos/{repo}"
    target = f"reports/{short_sha(sha) or 'latest'}/veracode-security-report.pdf"
    with open(path, "rb") as fh:
        content = base64.b64encode(fh.read()).decode("ascii")

    try:
        req("GET", f"{base}/branches/{branch}")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        repo_info = req("GET", base)
        head = req("GET", f"{base}/git/ref/heads/"
                          f"{repo_info['default_branch']}")
        req("POST", f"{base}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": head["object"]["sha"]})

    existing_sha = None
    try:
        meta = req("GET", f"{base}/contents/{target}?ref={branch}")
        if isinstance(meta, dict):
            existing_sha = meta.get("sha")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise

    payload = {
        "message": f"Veracode security report for {short_sha(sha)}",
        "content": content,
        "branch": branch,
    }
    if existing_sha:
        payload["sha"] = existing_sha
    req("PUT", f"{base}/contents/{target}", payload)
    return f"{server.rstrip('/')}/{repo}/blob/{branch}/{target}"


STATE_RE = re.compile(r"<!--\s*veracode-report-state:\s*(\{.*?\})\s*-->",
                      re.DOTALL)


def encode_state(ctx: "ReportContext") -> str:
    """Per-scan summary embedded in the comment, keyed to the commit."""
    scans = {}
    for scan, frag in ctx.fragments.items():
        scans[scan] = {"counts": frag.get("counts") or {},
                       "total": int(frag.get("total") or 0),
                       "gated": int(frag.get("gated") or 0),
                       "threshold": str(frag.get("threshold", "")),
                       "run_url": str(frag.get("run_url", ""))}
    payload = {"sha": ctx.sha, "scans": scans}
    return ("<!-- veracode-report-state: "
            + json.dumps(payload, separators=(",", ":")) + " -->")


def carry_prior_scans(ctx: "ReportContext") -> List[str]:
    """Re-attach scans an earlier run published that this run cannot see.

    Sibling findings normally arrive through the Actions artifacts API, but
    that needs actions: read and the artifacts must still exist. When it fails,
    the scan that finishes last would otherwise rewrite the comment using only
    its own results, turning a report that correctly showed findings into one
    that says nothing was found. Reading the previous comment back makes the
    summary additive, so it can never regress.

    Only state recorded against the same commit is reused.
    """
    body = vf.fetch_pr_comment("report")
    if not body:
        return []
    match = STATE_RE.search(body)
    if not match:
        return []
    try:
        prior = json.loads(match.group(1))
    except ValueError:
        return []
    if not isinstance(prior, dict) or prior.get("sha") != ctx.sha:
        return []
    carried = []
    for scan, summary in (prior.get("scans") or {}).items():
        if scan not in SCAN_IDS or scan in ctx.fragments:
            continue
        if not isinstance(summary, dict):
            continue
        ctx.fragments[scan] = {
            "scan": scan, "scan_label": SCAN_LABEL[scan],
            "counts": {b: int((summary.get("counts") or {}).get(b, 0))
                       for b in BANDS},
            "total": int(summary.get("total") or 0),
            "gated": int(summary.get("gated") or 0),
            "threshold": summary.get("threshold", "?"),
            "run_url": summary.get("run_url", ""),
            "findings": [], "advisories": [], "summary_only": True,
        }
        carried.append(scan)
    ctx.missing = [s for s in SCAN_IDS if s not in ctx.fragments]
    if carried:
        print(f"Carried forward {', '.join(SCAN_SHORT[s] for s in carried)} "
              f"from the existing comment for this commit.")
    return carried


def build_comment(ctx: ReportContext, pdf_url: str, pdf_name: str,
                  branch_hosted: bool) -> str:
    artifact_repo = env("ARTIFACT_REPO")
    offsite = bool(artifact_repo and ctx.repo and artifact_repo != ctx.repo)
    failed = ctx.gated_total > 0
    if failed:
        badge = f"{ctx.gated_total} finding(s) at or above threshold"
    elif not ctx.complete:
        badge = (f"Incomplete coverage: "
                 f"{len(SCAN_IDS) - len(ctx.missing)} of {len(SCAN_IDS)} scans "
                 f"reported, nothing above threshold so far")
    else:
        badge = "No findings at or above threshold"
    counts = ctx.totals()
    dot = {"critical": "\U0001f534", "high": "\U0001f7e0",
           "medium": "\U0001f7e1", "low": "\U0001f535", "info": "\u26aa"}

    lines = [
        "## Veracode Security Report",
        "",
        f"> **{badge}**  ",
        f"> {ctx.finding_total} finding(s) across SAST, SCA and IaC/Secrets "
        f"\u00b7 **{ctx.gated_total}** at or above threshold",
        "",
        "| " + " | ".join(f"{dot[b]} {b.capitalize()}" for b in BANDS)
        + " | Total |",
        "|:--:|:--:|:--:|:--:|:--:|:--:|",
        "| " + " | ".join(str(counts[b]) for b in BANDS)
        + f" | **{ctx.finding_total}** |",
        "",
        "| Scan | Status | Threshold | Findings | At or above |",
        "|:--|:--|:--:|--:|--:|",
    ]
    for scan in SCAN_IDS:
        frag = ctx.fragments.get(scan)
        if not frag:
            lines.append(f"| {SCAN_LABEL[scan]} | _pending_ | - | - | - |")
            continue
        gated = int(frag.get("gated") or 0)
        result = f"\u26a0\ufe0f {gated} to review" if gated else "\u2705 Clear"
        lines.append(f"| {SCAN_LABEL[scan]} | {result} | "
                     f"`{frag.get('threshold', '?')}` | "
                     f"{frag.get('total', 0)} | **{gated}** |")
    lines.append("")

    if not pdf_url:
        lines += ["> \u26a0\ufe0f The report could not be linked from this "
                  "run. The findings below are the summary; the PDF is "
                  f"attached to the workflow run as `{pdf_name}`."]
    elif branch_hosted:
        lines += [f"### \U0001f4c4 [Open the full PDF report]({pdf_url})", "",
                  "Opens in the browser with every finding, its exact location "
                  "and remediation detail."]
    elif offsite:
        lines += [f"### \U0001f4c4 [Download the full PDF report]({pdf_url})",
                  "",
                  f"Every finding with its exact location and remediation "
                  f"detail, as the `{pdf_name}` artifact. The scan ran in "
                  f"`{artifact_repo}`, so the link needs read access there. "
                  f"Without it, the tables above are the full summary."]
    else:
        lines += [f"### \U0001f4c4 [Download the full PDF report]({pdf_url})",
                  "",
                  f"Every finding with its exact location and remediation "
                  f"detail. Open the workflow run and download the "
                  f"`{pdf_name}` artifact."]
    lines.append("")

    ranked = sorted(ctx.all_findings, key=_sort_key)[:5]
    if ranked:
        lines += ["<details>",
                  "<summary><b>Highest-severity findings</b></summary>", "",
                  "| Severity | Scan | ID | Finding | Location |",
                  "|:--|:--|:--|:--|:--|"]
        for rec in ranked:
            # Titles, identifiers and paths all originate in scanner output.
            # Escaping only the title left the other two able to break out of
            # a link label or a table cell.
            ident = vf.md_escape(rec.get("ident"), 40) or "-"
            if rec.get("ident_url"):
                ident = f"[{ident}]({rec['ident_url']})"
            loc = vf.md_escape(_location_text(rec), 60)
            if rec.get("url"):
                base = vf.md_escape(loc.rsplit("/", 1)[-1], 40)
                loc = f"[{base}]({rec['url']})"
            lines.append(
                f"| {dot[rec.get('band', 'info')]} "
                f"{rec.get('band', 'info').capitalize()} | "
                f"{SCAN_SHORT.get(rec.get('scan', ''), '')} | {ident} | "
                f"{vf.md_escape(rec.get('title'), 110)} | {loc} |")
        lines += ["", "</details>", ""]

    if ctx.missing:
        names = ", ".join(SCAN_SHORT[s] for s in ctx.missing)
        lines.append(f"> \u2139\ufe0f {names} has not reported for this commit "
                     f"yet. This comment and the PDF are rebuilt as each scan "
                     f"finishes.")
        lines.append("")
    lines.append("<sub>Generated by the Veracode GitHub workflow "
                 "integration.</sub>")
    lines.append(encode_state(ctx))
    return "\n".join(lines)


def write_job_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    except OSError as exc:
        print(f"::warning::Could not write the job summary: {exc}")


def build_report(args: argparse.Namespace) -> int:
    fragments_dir = args.fragments
    if args.collect:
        collect_fragments(fragments_dir, env("HEAD_SHA"), env("ARTIFACT_REPO"),
                          env("ARTIFACT_TOKEN") or env("GITHUB_TOKEN"),
                          env("GITHUB_API_URL", "https://api.github.com"))

    fragments = load_fragments(fragments_dir)
    if not fragments:
        print("::warning::No scan fragments found; no report produced.")
        return 0

    ctx = ReportContext(fragments)
    carry_prior_scans(ctx)
    try:
        render_pdf(ctx, args.out, args.page_size, args.max_detail)
    except Exception as exc:
        print(f"::error::Could not render the PDF report: {exc}")
        return 1
    size_kb = os.path.getsize(args.out) / 1024.0
    print(f"Wrote {args.out} ({size_kb:.0f} KB) covering "
          f"{', '.join(SCAN_SHORT[s] for s in SCAN_IDS if s in fragments)}.")

    api = env("GITHUB_API_URL", "https://api.github.com")
    pdf_name = args.artifact_name
    pdf_url = ""
    branch_hosted = False

    if args.publish_branch:
        try:
            pdf_url = publish_to_branch(
                args.out, args.publish_branch, ctx.repo,
                env("GH_TOKEN") or env("GITHUB_TOKEN"), api, ctx.sha,
                ctx.server)
            branch_hosted = True
            print(f"Published the report to {pdf_url}")
        except Exception as exc:
            print(f"::warning::Could not publish the report to branch "
                  f"'{args.publish_branch}' ({exc}); linking the workflow "
                  f"artifact instead. Branch publishing needs a token with "
                  f"Contents: write on '{ctx.repo}'. The workflow's own "
                  f"GITHUB_TOKEN is deliberately limited to contents: read, "
                  f"so pass a separate token as the comment_token secret.")

    if not pdf_url:
        pdf_url = artifact_deep_link(
            ctx.server, env("ARTIFACT_REPO"), env("GITHUB_RUN_ID"), pdf_name,
            env("ARTIFACT_TOKEN") or env("GITHUB_TOKEN"), api)

    markdown = build_comment(ctx, pdf_url, pdf_name, branch_hosted)
    write_job_summary(markdown)

    if args.pr_comment:
        post_comment(markdown)
    return 0


def post_comment(markdown: str) -> None:
    try:
        vf.upsert_pr_comment("report", markdown)
    except Exception as exc:
        print(f"::warning::Could not update the report PR comment ({exc}).")


def comment_only(args: argparse.Namespace) -> int:
    """Post the sticky comment after the PDF artifact has been uploaded.

    Run as its own step so the artifact exists by the time its download link is
    resolved. Without this split the link can only ever point at the run page.
    """
    fragments = load_fragments(args.fragments)
    if not fragments:
        print("::warning::No scan fragments found; no comment posted.")
        return 0
    ctx = ReportContext(fragments)
    carry_prior_scans(ctx)
    pdf_url = args.pdf_url or artifact_deep_link(
        ctx.server, env("ARTIFACT_REPO"), env("GITHUB_RUN_ID"),
        args.artifact_name, env("ARTIFACT_TOKEN") or env("GITHUB_TOKEN"),
        env("GITHUB_API_URL", "https://api.github.com"))
    markdown = build_comment(ctx, pdf_url, args.artifact_name,
                             bool(args.pdf_url))
    write_job_summary(markdown)
    post_comment(markdown)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Build a consolidated Veracode PDF report from SAST, SCA "
                    "and IaC/Secrets findings.")
    sub = ap.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("export", help="Normalize one scan's results into a "
                                       "fragment for the report.")
    ex.add_argument("--mode", required=True, choices=SCAN_IDS)
    ex.add_argument("--input", required=True, nargs="+",
                    help="Results file(s). The pipeline scan is matrixed over "
                         "packaged modules, so pass every N-results.json")
    ex.add_argument("--threshold", default="medium",
                    help="critical|high|medium|low|info or a CVSS number")
    ex.add_argument("--include-outdated", action="store_true",
                    help="SCA text mode: also include Outdated Library issues")
    ex.add_argument("--config", default=None,
                    help="Local veracode.yml to read "
                         "break_build_severity_threshold from. Only useful if "
                         "you added that key yourself; it is not part of a "
                         "stock Veracode integration")
    ex.add_argument("--out", required=True, help="Fragment JSON to write")

    bd = sub.add_parser("build", help="Render the PDF from collected fragments.")
    bd.add_argument("--fragments", default="veracode-report-fragments",
                    help="Directory holding fragment JSON files")
    bd.add_argument("--collect", action="store_true",
                    help="Also pull sibling scan fragments for this commit "
                         "from the Actions artifacts API")
    bd.add_argument("--out", default="veracode-security-report.pdf")
    bd.add_argument("--page-size", default="a4", choices=["a4", "letter"])
    bd.add_argument("--max-detail", type=int, default=250,
                    help="Maximum full-detail finding cards before the "
                         "remainder is summarized in a table")
    bd.add_argument("--artifact-name", default="veracode-security-report",
                    help="Name of the uploaded artifact, used for the link")
    bd.add_argument("--publish-branch", default=None,
                    help="Commit the PDF to this branch of the scanned repo "
                         "so the comment links to a browser-rendered file. "
                         "Requires Contents: write on the dispatch token.")
    bd.add_argument("--pr-comment", action="store_true",
                    help="Post the comment from this step. Prefer the separate "
                         "'comment' command so the artifact link resolves.")

    cm = sub.add_parser("comment", help="Post the sticky PR comment, after the "
                                        "PDF artifact has been uploaded.")
    cm.add_argument("--fragments", default="veracode-report-fragments")
    cm.add_argument("--artifact-name", default="veracode-security-report")
    cm.add_argument("--pdf-url", default=None,
                    help="Link to use instead of resolving the artifact")
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "export":
        return export_fragment(args)
    if args.command == "comment":
        return comment_only(args)
    return build_report(args)


if __name__ == "__main__":
    sys.exit(main())
