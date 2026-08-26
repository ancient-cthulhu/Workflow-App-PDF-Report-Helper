#!/usr/bin/env python3
"""Veracode scan-result normalization.

Parses the three Veracode scans into one Finding shape, applies a single
severity model, and provides the GitHub helpers the report needs: source links,
path resolution and sticky pull-request comments.

Self-contained: standard library only, no dependency on any other helper.

Inputs:
  pipeline  Static pipeline scan results.json / filtered_results.json
  sca       Agent-based SCA, either scaResults.txt or scaResults.json
  iac       Veracode CLI `veracode scan --format json`

Every finding is ranked on the higher of its severity label and the band from
its CVSS base score, so one labelled Unknown carrying a high score is not
under-rated. With no usable signal it is floored, not treated as
informational: secrets to high, everything else to medium.

Nothing here gates a build. Thresholds only mark which findings sit at or above
the configured level, so the report can say where to start.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

SIGNAL_RANK: Dict[str, int] = {
    "info": 0, "informational": 0, "none": 0, "negligible": 0,
    "low": 1,
    "medium": 2, "moderate": 2,
    "high": 3,
    "critical": 4, "very high": 4,
}
NON_SIGNAL_LABELS = {"", "unknown", "undefined", "unassigned"}

RANK_TO_BAND = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
BANDS = ["critical", "high", "medium", "low", "info"]

FLOOR_SECRET = SIGNAL_RANK["high"]
FLOOR_DEFAULT = SIGNAL_RANK["medium"]

SCAN_IDS = ["pipeline", "sca", "iac"]


class FindingsError(Exception):
    """Raised when results cannot be parsed into a trustworthy finding set."""


def cvss_to_label(score: Any) -> str:
    """Map a CVSS base score to a qualitative band (CVSS v3 banding)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value != value:
        return "unknown"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "info"


def label_rank(label: Optional[str]) -> Optional[int]:
    key = (label or "").strip().lower()
    if key in NON_SIGNAL_LABELS:
        return None
    return SIGNAL_RANK.get(key)


def cvss_rank(cvss: Any) -> Optional[int]:
    if cvss is None:
        return None
    return SIGNAL_RANK.get(cvss_to_label(cvss))


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize(text: Optional[str], limit: int) -> str:
    """Make a finding string safe for a Markdown cell and for workflow logs.

    Collapses newlines and tabs (which would split a table row or be read as a
    workflow command), neutralizes a leading '::', escapes pipes, truncates.
    """
    s = text or ""
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # Strip ANSI sequences and other control characters. They are invisible in
    # a comment but can reposition the cursor or recolour workflow logs, so a
    # crafted finding title could forge log output.
    s = _ANSI_RE.sub("", s)
    s = _CTRL_RE.sub("", s)
    s = re.sub(r"\s+", " ", s).strip()
    if s.startswith("::"):
        s = s.replace("::", ": ", 1)
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "\u2026"
    return s.replace("|", "\\|")


_PATH_PREFIXES = [
    re.compile(r"^__w/[^/]+/[^/]+/"),
    re.compile(r"^home/[^/]+/work/[^/]+/[^/]+/"),
    re.compile(r"^github/workspace/"),
    re.compile(r"^runner/work/[^/]+/[^/]+/"),
    re.compile(r"^source-code/"),
    re.compile(r"^veracode_artifact_directory/"),
]

_VERSION_RE = re.compile(r"^v?\d[\w.\-+]*$")


_MD_SPECIALS = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def md_escape(text: Optional[str], limit: int) -> str:
    """Sanitize, then escape Markdown so scanner text cannot alter structure.

    sanitize() alone handles pipes and newlines, which protects table cells,
    but a value used as a link label also needs brackets and parentheses
    escaped: a finding titled "a](javascript:alert(1))[b" would otherwise close
    the label and supply its own target.
    """
    return _MD_SPECIALS.sub(r"\\\1", sanitize(text, limit).replace("\\|", "|"))


def clean_path(path: Optional[str]) -> str:
    """Reduce an absolute build path to a readable, repo-relative one."""
    p = (path or "").replace("\\", "/").strip().lstrip("/")
    if not p or p.upper() == "UNKNOWN":
        return ""
    changed = True
    while changed:
        changed = False
        for pattern in _PATH_PREFIXES:
            new = pattern.sub("", p)
            if new != p:
                p, changed = new, True
    return p


def split_name_version(s: str) -> Tuple[str, str]:
    """Split 'library 1.2.3' into ('library', '1.2.3').

    The trailing token must look like a version, otherwise the whole string is
    treated as the name.
    """
    s = (s or "").strip()
    if " " in s:
        name, _, ver = s.rpartition(" ")
        if _VERSION_RE.match(ver):
            return name.strip(), ver.strip()
    return s, ""


def github_blob_url(file: str, line: Optional[int]) -> Optional[str]:
    """Link a repo-relative path to its source on GitHub, when resolvable.

    BLOB_REF (a branch) overrides HEAD_SHA, because the SAST dispatch can carry
    a SHA that is not a browsable commit.
    """
    repo = os.environ.get("SCAN_REPO")
    ref = os.environ.get("BLOB_REF") or os.environ.get("HEAD_SHA")
    if not (repo and ref and file):
        return None
    base = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    url = f"{base}/{repo}/blob/{ref}/{file}"
    if line:
        url += f"#L{line}"
    return url


def id_url(ident: Optional[str]) -> Optional[str]:
    """Authoritative reference for a CWE, CVE or GHSA identifier."""
    s = (ident or "").strip()
    m = re.match(r"^CWE-(\d+)$", s, re.IGNORECASE)
    if m:
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    if re.match(r"^CVE-\d{4}-\d+$", s, re.IGNORECASE):
        return f"https://nvd.nist.gov/vuln/detail/{s.upper()}"
    if re.match(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", s, re.IGNORECASE):
        return f"https://github.com/advisories/{s}"
    return None


def safe_url(url: Optional[str]) -> str:
    """Return `url` only if it is an absolute http(s) URL, else "".

    Scanner output is untrusted: advisory references and vulnerability URLs are
    copied from the scanned project's own dependency metadata. Anything reaching
    a PDF link annotation or a Markdown link goes through here first, because a
    javascript: URI in an annotation is executable in several PDF viewers.
    """
    s = (url or "").strip()
    if not s or len(s) > 2000:
        return ""
    if any(c in s for c in "\n\r\t <>\"'\\`"):
        return ""
    return s if re.match(r"^https?://[^\s/@]+\.[^\s]+$", s, re.IGNORECASE) else ""


def extract_report_url(raw: str) -> Optional[str]:
    """Pull the Veracode platform report URL out of a text report, if present."""
    m = re.search(r"https://[^\s\"']*analysiscenter\.veracode\.com/[^\s\"']+",
                  raw or "")
    return m.group(0) if m else None


class Finding:
    __slots__ = ("category", "severity", "ident", "title", "location", "cvss",
                 "floor", "file", "line", "fix", "cve", "version", "ref_url",
                 "detail", "function", "scope", "detail_url", "native_id",
                 "code")

    def __init__(self, category: str, severity: Optional[str],
                 ident: Optional[str], title: Optional[str],
                 location: Optional[str], cvss: Any = None,
                 floor: int = FLOOR_DEFAULT, file: Optional[str] = None,
                 line: Optional[int] = None, fix: Optional[str] = None,
                 cve: Optional[str] = None, version: Optional[str] = None,
                 ref_url: Optional[str] = None, detail: Optional[str] = None,
                 function: Optional[str] = None, scope: Optional[str] = None,
                 detail_url: Optional[str] = None,
                 native_id: Optional[str] = None,
                 code: Optional[str] = None) -> None:
        self.category = category
        self.severity = severity
        self.ident = ident or ""
        self.title = title or ""
        self.location = location or ""
        self.cvss = cvss
        self.floor = floor
        self.file = file or ""
        self.line = line
        self.fix = fix or ""
        self.cve = cve or ""
        self.version = version or ""
        self.ref_url = ref_url or ""
        self.detail = detail or ""
        self.function = function or ""
        self.scope = scope or ""
        self.detail_url = detail_url or ""
        self.native_id = native_id or ""
        self.code = code or ""

    @property
    def effective_rank(self) -> int:
        ranks = [r for r in (label_rank(self.severity), cvss_rank(self.cvss))
                 if r is not None]
        return max(ranks) if ranks else self.floor

    @property
    def band(self) -> str:
        return RANK_TO_BAND[self.effective_rank]


def _cvss_from_match(vuln: Dict[str, Any]) -> Optional[float]:
    for entry in (vuln.get("cvss") or []):
        base = (entry.get("metrics") or {}).get("baseScore")
        if base is not None:
            try:
                return float(base)
            except (TypeError, ValueError):
                return None
    return None


_SECRETY_KEY_RE = re.compile(
    r"(?i)\b([A-Z0-9_\-.]*(?:PASS(?:WORD)?|SECRET|TOKEN|APIKEY|API_KEY|KEY|"
    r"CREDENTIAL|AUTH)[A-Z0-9_\-.]*)\s*([=:])\s*(\S+)")


def redact(text: str) -> str:
    """Mask assigned values whose key names a credential.

    A misconfiguration's offending line is the most useful thing in the report,
    but the line that triggers "secret passed via env" contains the secret
    itself. Echoing it into a PR comment or a retained artifact would leak the
    credential wider than the commit already does.
    """
    return _SECRETY_KEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]",
                               text or "")


def _config_snippet(cause: Dict[str, Any]) -> str:
    """The offending source line, redacted, as 'NN: content'."""
    lines = ((cause.get("Code") or {}).get("Lines") or [])
    for entry in lines:
        if entry.get("IsCause") or entry.get("FirstCause"):
            content = (entry.get("Content") or "").strip()
            if not content:
                continue
            number = entry.get("Number")
            snippet = redact(content)
            return f"{number}: {snippet}" if number else snippet
    return ""


def parse_iac(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise FindingsError("IaC results are not a JSON object.")
    findings: List[Finding] = []

    for match in ((data.get("vulnerabilities") or {}).get("matches") or []):
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}

        fixobj = vuln.get("fix") or {}
        versions = fixobj.get("versions") or []
        if versions:
            fix = ", ".join(str(v) for v in versions)
        else:
            state = (fixobj.get("state") or "").lower()
            fix = {"not-fixed": "not fixed", "wont-fix": "won't fix",
                   "unknown": "", "": ""}.get(state, state.replace("-", " "))

        cve = ""
        for related in (match.get("relatedVulnerabilities") or []):
            rid = str(related.get("id") or "")
            if rid.upper().startswith("CVE-"):
                cve = rid.upper()
                break

        manifest = ""
        for loc in (artifact.get("locations") or []):
            path = loc.get("path") or loc.get("RealPath") or ""
            if path:
                manifest = clean_path(path)
                break

        urls = [u for u in (vuln.get("urls") or []) if isinstance(u, str)]
        findings.append(Finding(
            "Vulnerability", vuln.get("severity"), vuln.get("id"),
            vuln.get("description") or vuln.get("id"),
            artifact.get("name", ""), _cvss_from_match(vuln), FLOOR_DEFAULT,
            file=manifest, fix=fix, cve=cve,
            version=artifact.get("version", ""),
            detail=vuln.get("description") or "",
            scope=artifact.get("type") or "",
            detail_url=safe_url(urls[0]) if urls else ""))

    for secret in (data.get("secrets") or []):
        line = secret.get("StartLine") or secret.get("startLine")
        target = secret.get("Target") or secret.get("target") or ""
        rule = secret.get("RuleID") or secret.get("ruleID")
        loc = target if not line else f"{target}:{line}"
        findings.append(Finding(
            "Secret",
            secret.get("Severity") or secret.get("severity"),
            rule,
            secret.get("Title") or rule or secret.get("Category")
            or "Exposed secret",
            loc, None, FLOOR_SECRET,
            file=clean_path(target),
            line=line if isinstance(line, int) else None,
            scope=secret.get("Category") or secret.get("category") or "",
            detail=(f"Matched the '{rule}' secret pattern. Treat the value as "
                    f"compromised: revoke and rotate it, then remove it from "
                    f"the repository history." if rule else "")))

    for config in (data.get("configs") or []):
        if str(config.get("Status", "FAIL")).upper() == "PASS":
            continue
        cause = config.get("CauseMetadata") or {}
        provider = cause.get("Provider", "")
        target = config.get("Target", "")
        start = cause.get("StartLine")
        loc = target if provider in ("", target) else f"{provider}: {target}"
        ref_url = ""
        for url in (config.get("References") or config.get("references") or []):
            if isinstance(url, str) and "aquasec" not in url.lower():
                ref_url = safe_url(url)
                if ref_url:
                    break
        # Resolution states the fix; Message only restates the problem.
        message = (config.get("Resolution") or config.get("Message")
                   or config.get("message") or "")
        findings.append(Finding(
            "Misconfiguration",
            config.get("Severity") or config.get("severity"),
            config.get("ID"), config.get("Title") or message, loc, None,
            FLOOR_DEFAULT, file=clean_path(target),
            line=start if isinstance(start, int) else None,
            ref_url=ref_url, fix=message,
            detail=config.get("Description") or "",
            scope=cause.get("Service") or provider or "",
            code=_config_snippet(cause)))

    return findings


def _resolve_library(data: Dict[str, Any], ref: str) -> str:
    try:
        parts = ref.strip("/").split("/")
        record_idx = int(parts[parts.index("records") + 1])
        lib_idx = int(parts[parts.index("libraries") + 1])
        lib = data["records"][record_idx]["libraries"][lib_idx]
        return lib.get("name") or lib.get("coordinate1") or ""
    except (ValueError, KeyError, IndexError, TypeError):
        return ""


def parse_sca_json(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise FindingsError("SCA results are not a JSON object.")
    findings: List[Finding] = []
    for record in data.get("records") or []:
        for vuln in record.get("vulnerabilities") or []:
            score = vuln.get("cvss3Score")
            if score is None:
                score = vuln.get("cvssScore")
            libname = ""
            for lib in (vuln.get("libraries") or []):
                ref = (lib.get("_links") or {}).get("ref", "")
                libname = _resolve_library(data, ref) or libname
            findings.append(Finding(
                "Vulnerability", cvss_to_label(score),
                vuln.get("cve") or vuln.get("title"), vuln.get("title"),
                libname, score,
                detail=vuln.get("overview") or vuln.get("description") or ""))
    return findings


ISSUE_ROW = re.compile(
    r"^\s*(\d{6,})\s+"
    r"(Vulnerability|Outdated Library)\s+"
    r"(\d+(?:\.\d+)?)\s+"
    r"(.*?)\s{2,}"
    r"(\S.*\S)\s*$"
)
SUMMARY_ROW = re.compile(
    r"^\s*(Critical|High|Medium|Low)\s+Risk\s+Vulnerabilities\s+(\d+)\s*$",
    re.IGNORECASE,
)


def parse_sca_summary(text: str) -> Optional[int]:
    """Total vulnerabilities the agent summary reports, or None if absent."""
    total = 0
    seen = False
    for line in text.splitlines():
        m = SUMMARY_ROW.match(line)
        if m:
            seen = True
            total += int(m.group(2))
    return total if seen else None


def parse_sca_text(text: str, include_outdated: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    in_issues = False
    for line in text.splitlines():
        if line.strip().startswith("Issue ID") and "Severity" in line:
            in_issues = True
            continue
        if not in_issues:
            continue
        if line.strip().startswith("Full Report Details"):
            break
        m = ISSUE_ROW.match(line)
        if not m:
            continue
        issue_id, issue_type, cvss, desc, lib = m.groups()
        if issue_type == "Outdated Library" and not include_outdated:
            continue
        desc = desc.strip()
        cve = re.match(r"(CVE-\d{4}-\d+)\s*:?\s*(.*)", desc, re.IGNORECASE)
        if cve:
            ident = cve.group(1).upper()
            title = cve.group(2).strip() or desc
        else:
            ident = issue_id
            title = desc
        name, ver = split_name_version(lib.strip())
        findings.append(Finding(
            "Vulnerability" if issue_type == "Vulnerability"
            else "Outdated Library",
            cvss_to_label(cvss), ident, title, name, float(cvss),
            version=ver, native_id=issue_id))
    return findings


def parse_sca_update_advisor(text: str) -> List[Dict[str, str]]:
    """Parse the agent's Update Advisor section, if the scan produced one.

    Header-driven so it adapts to whichever columns the agent emits. Returns []
    when the section is absent or cannot be parsed.
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"\s*update advisor\b", line, re.IGNORECASE):
            start = i
            break
    if start is None:
        return []

    header = None
    header_idx = None
    for j in range(start + 1, min(start + 10, len(lines))):
        s = lines[j].strip()
        if not s or set(s) <= set("=-_ "):
            continue
        cols = re.split(r"\s{2,}", s)
        if len(cols) >= 2 and re.search(r"(?i)breaking|version|update|librar", s):
            header = [c.strip().lower() for c in cols]
            header_idx = j
            break
    if not header:
        return []

    def col_index(*names: str) -> Optional[int]:
        for k, h in enumerate(header):
            if any(n in h for n in names):
                return k
        return None

    i_lib = col_index("librar")
    i_lib = 0 if i_lib is None else i_lib
    i_use = col_index("in use", "current", "installed")
    i_to = col_index("safe", "update to", "recommend", "update", "fixed")
    i_brk = col_index("breaking")
    i_fixes = col_index("vulnerabilit", "fixes", "issues")

    def cell(cols: List[str], idx: Optional[int]) -> str:
        return cols[idx].strip() if (idx is not None and idx < len(cols)) else ""

    rows: List[Dict[str, str]] = []
    for line in lines[header_idx + 1:]:
        s = line.strip()
        if not s:
            if rows:
                break
            continue
        if set(s) <= set("=-_ "):
            continue
        if re.match(r"(?i)(full report details|update advisor)", s):
            break
        cols = [c.strip() for c in re.split(r"\s{2,}", s)]
        if len(cols) < 2:
            break
        rows.append({
            "library": cell(cols, i_lib),
            "in_use": cell(cols, i_use),
            "update_to": cell(cols, i_to),
            "breaking": cell(cols, i_brk),
            "fixes": cell(cols, i_fixes),
        })
    for row in rows:
        if not row["in_use"] and row["library"]:
            name, ver = split_name_version(row["library"])
            if ver:
                row["library"], row["in_use"] = name, ver
    return rows


def backfill_advisor_in_use(advisories: List[Dict[str, str]],
                            findings: Sequence[Finding]) -> None:
    """Fill an empty advisor 'in use' version from the parsed issue list."""
    if not advisories:
        return
    version_by_lib: Dict[str, str] = {}
    for f in findings:
        if f.location and f.version:
            version_by_lib.setdefault(f.location.strip().lower(), f.version)
    for advisory in advisories:
        if advisory.get("in_use"):
            continue
        lib_raw = re.sub(r"\s*\([^)]*\)\s*$", "",
                         advisory.get("library", "")).strip()
        name, ver = split_name_version(lib_raw)
        advisory["in_use"] = ver or version_by_lib.get(
            name.lower(), version_by_lib.get(lib_raw.lower(), ""))


PIPELINE_SEVERITY = {5: "critical", 4: "high", 3: "medium", 2: "low",
                     1: "low", 0: "info"}


def parse_pipeline(data: Any) -> List[Finding]:
    if not isinstance(data, dict):
        raise FindingsError("Pipeline results are not a JSON object.")
    findings: List[Finding] = []
    for entry in data.get("findings") or []:
        try:
            band = PIPELINE_SEVERITY.get(int(entry.get("severity")))
        except (TypeError, ValueError):
            band = None
        source = (entry.get("files") or {}).get("source_file") or {}
        rel = clean_path(source.get("file", ""))
        try:
            line = int(source.get("line")) if source.get("line") else None
        except (TypeError, ValueError):
            line = None
        loc = (rel + (f":{line}" if line else "")) if rel else ""
        cwe = entry.get("cwe_id")
        ident = (f"CWE-{cwe}" if cwe not in (None, "")
                 else (entry.get("issue_type_id")
                       or str(entry.get("issue_id") or "")))
        detail_url = entry.get("flaw_details_link") or ""
        findings.append(Finding(
            "Flaw", band, ident,
            entry.get("issue_type") or entry.get("display_text")
            or entry.get("title"),
            loc, None, FLOOR_DEFAULT, file=rel, line=line,
            detail=entry.get("display_text") or "",
            function=(source.get("qualified_function_name")
                      or source.get("function_name") or ""),
            scope=source.get("scope") or "",
            detail_url=safe_url(detail_url),
            native_id=str(entry.get("issue_id") or "")))
    return findings


class Threshold:
    """A validated gate threshold: a named band, or an exact CVSS cut."""

    def __init__(self, raw: str) -> None:
        self.raw = str(raw).strip()
        self.numeric: Optional[float] = None
        key = self.raw.lower()
        if key in SIGNAL_RANK:
            self.rank = SIGNAL_RANK[key]
            return
        try:
            value = float(self.raw)
        except ValueError:
            raise FindingsError(
                f"Invalid threshold '{raw}'. Use one of "
                f"{sorted(set(SIGNAL_RANK))} or a CVSS number in [0, 10].")
        if value != value or value < 0.0 or value > 10.0:
            raise FindingsError(
                f"Invalid threshold '{raw}'. A numeric threshold must be a "
                f"finite value in [0, 10].")
        self.numeric = value
        self.rank = SIGNAL_RANK[cvss_to_label(value)]

    def gates(self, finding: Finding) -> bool:
        if self.numeric is not None and finding.cvss is not None:
            try:
                return float(finding.cvss) >= self.numeric
            except (TypeError, ValueError):
                pass
        return finding.effective_rank >= self.rank


def read_yaml_threshold(path: str, section: str) -> str:
    """Read break_build_severity_threshold from one veracode.yml section.

    A deliberately narrow reader rather than a YAML parse: it needs no
    dependency, and it only ever returns a scalar that is validated by
    Threshold before use. Returns "" when the key or section is absent.
    """
    if not (path and section and os.path.exists(path)):
        return ""
    in_section = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if re.match(r"^" + re.escape(section) + r"\s*:\s*$", line):
                    in_section = True
                    continue
                if re.match(r"^[^\s#]", line):
                    in_section = False
                if not in_section:
                    continue
                m = re.match(
                    r"^\s*break_build_severity_threshold\s*:\s*(.+?)\s*$", line)
                if m:
                    value = re.sub(r"\s+#.*$", "", m.group(1)).strip()
                    return value.strip("\"'")
    except OSError:
        return ""
    return ""


def resolve_threshold(config_paths: Sequence[str], section: str,
                      *fallbacks: Optional[str]) -> str:
    """First non-empty threshold, in precedence order.

    Repository veracode.yml, then the integration repo's veracode.yml, then any
    caller-supplied fallbacks (dispatch payload, Actions variable), then the
    built-in default of medium. Mirrors the severity gate's resolution order so
    both controls read the same value.
    """
    for path in config_paths:
        value = read_yaml_threshold(path, section)
        if value:
            return value
    for value in fallbacks:
        if value and str(value).strip():
            return str(value).strip()
    return "medium"


def load_findings(mode: str, raw: str,
                  include_outdated: bool = False) -> List[Finding]:
    """Parse raw scan output for `mode` into findings.

    In sca mode the format is auto-detected: a payload starting with '{' or '['
    is the JSON report, anything else is the agent text report.
    """
    if mode == "iac":
        try:
            return parse_iac(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise FindingsError(f"IaC results are not valid JSON: {exc}.")

    if mode == "pipeline":
        try:
            return parse_pipeline(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise FindingsError(f"Pipeline results are not valid JSON: {exc}.")

    if mode != "sca":
        raise FindingsError(f"Unknown scan mode '{mode}'.")

    if raw.lstrip()[:1] in ("{", "["):
        try:
            return parse_sca_json(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise FindingsError(f"SCA results are not valid JSON: {exc}.")

    findings = parse_sca_text(raw, include_outdated=include_outdated)
    _assert_sca_complete(raw, findings)
    return findings


def _assert_sca_complete(text: str, findings: Sequence[Finding]) -> None:
    """Refuse to report a partial SCA parse as a complete one.

    The issue table is located by matching its header row. If the agent renames
    a column, the header stops matching and every row is skipped: the scan then
    reports zero findings and the report renders clean. That is the worst
    failure this tool can have, so the agent's own summary counts are used as
    an independent check. Raising here makes the caller mark the scan as
    pending rather than passing.
    """
    expected = parse_sca_summary(text)
    if expected is None:
        return
    parsed = sum(1 for f in findings if f.category == "Vulnerability")
    if parsed < expected:
        raise FindingsError(
            f"SCA summary reports {expected} vulnerability finding(s) but only "
            f"{parsed} row(s) could be parsed. The report would understate the "
            f"risk, so this scan is being marked as not reported. The agent's "
            f"issue-table format has probably changed.")


def gh_request(api: str, method: str, path_or_url: str, token: str,
               payload: Optional[dict] = None):
    import urllib.request
    url = (path_or_url if path_or_url.startswith("http")
           else api.rstrip("/") + path_or_url)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=45) as resp:
        body = resp.read()
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            return resp.status, json.loads(body.decode("utf-8") or "null")
        return resp.status, body


def _fetch_tree_paths(api: str, repo: str, ref: str,
                      token: str) -> Dict[str, str]:
    """Map lowercased repo paths to their real-case path, for one ref."""
    try:
        _, data = gh_request(
            api, "GET", f"/repos/{repo}/git/trees/{ref}?recursive=1", token)
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for entry in (data.get("tree") or []):
        if entry.get("type") == "blob" and entry.get("path"):
            out[entry["path"].lower()] = entry["path"]
    return out


def correct_file_cases(findings: Sequence[Finding]) -> None:
    """Map finding paths onto the repo's real paths so blob links resolve.

    Handles two scanner behaviours: case differences (SAST on .NET lowercases
    paths) and stripped prefixes (SAST on Java reports paths relative to the
    source root, dropping e.g. app/src/main/java/). Each path is resolved
    against the actual tree, first by case-insensitive match then by a unique
    suffix match. Best-effort: unmatched or ambiguous paths are left alone.
    """
    if not any(f.file for f in findings):
        return
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SCAN_REPO")
    ref = os.environ.get("BLOB_REF") or os.environ.get("HEAD_SHA")
    if not (token and repo and ref):
        return
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    tree = _fetch_tree_paths(api, repo, ref, token)
    if not tree:
        return

    by_base: Dict[str, List[Tuple[str, str]]] = {}
    for lower, real in tree.items():
        by_base.setdefault(lower.rsplit("/", 1)[-1], []).append((lower, real))

    for f in findings:
        if not f.file:
            continue
        lowered = f.file.replace("\\", "/").lstrip("/").lower()
        real = tree.get(lowered)
        if real:
            f.file = real
            continue
        candidates = [r for (lower, r)
                      in by_base.get(lowered.rsplit("/", 1)[-1], [])
                      if lower == lowered or lower.endswith("/" + lowered)]
        if len(candidates) == 1:
            f.file = candidates[0]


def _find_comment(api: str, repo: str, pr: str, token: str, marker: str):
    page = 1
    while page <= 10:
        _, items = gh_request(
            api, "GET",
            f"/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}",
            token)
        if not items:
            return None
        for comment in items:
            if marker in (comment.get("body") or ""):
                return comment
        if len(items) < 100:
            return None
        page += 1
    return None


def _resolve_pr_number(api: str, repo: str, sha: str,
                       token: str) -> Optional[str]:
    """Find the PR for a commit, so a scan can comment even when the dispatch
    does not forward pr_number."""
    try:
        _, items = gh_request(
            api, "GET", f"/repos/{repo}/commits/{sha}/pulls", token)
    except Exception:
        return None
    for pr in items or []:
        if pr.get("state") == "open" and pr.get("number"):
            return str(pr["number"])
    if items and items[0].get("number"):
        return str(items[0]["number"])
    return None


def comment_marker(marker_id: str) -> str:
    return f"<!-- veracode-report:{marker_id} -->"


def fetch_pr_comment(marker_id: str) -> Optional[str]:
    """Body of the existing sticky comment, or None.

    Lets a later scan recover what earlier scans already published, so the
    comment can never regress to a weaker result than it previously showed.
    """
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SCAN_REPO")
    pr = os.environ.get("PR_NUMBER")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not (token and repo and pr and str(pr).strip().isdigit()):
        return None
    try:
        existing = _find_comment(api, repo, pr, token,
                                 comment_marker(marker_id))
    except Exception:  # noqa: BLE001 - best-effort
        return None
    return (existing or {}).get("body")


def upsert_pr_comment(marker_id: str, body_md: str) -> bool:
    """Create or update a sticky pull-request comment identified by a marker.

    Best-effort: any failure prints a warning and returns False without
    affecting the caller's outcome. Reads GH_TOKEN, SCAN_REPO, PR_NUMBER and
    optional GITHUB_API_URL from the environment. The marker is distinct from
    the severity gate's, so the two coexist without overwriting each other.
    """
    import random
    import time
    import urllib.error

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SCAN_REPO")
    pr = os.environ.get("PR_NUMBER")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not (token and repo):
        print("::warning::PR comment skipped: GH_TOKEN/SCAN_REPO not set.")
        return False
    if not (pr and str(pr).strip().isdigit()):
        sha = os.environ.get("HEAD_SHA")
        resolved = _resolve_pr_number(api, repo, sha, token) if sha else None
        if not resolved:
            print("::warning::PR comment skipped: no PR_NUMBER and no pull "
                  "request could be resolved from the commit (this run may "
                  "not be a pull request).")
            return False
        pr = resolved
        print(f"Resolved PR #{pr} from the commit SHA.")

    marker = comment_marker(marker_id)
    body = f"{marker}\n{body_md}"
    for attempt in range(4):
        try:
            existing = _find_comment(api, repo, pr, token, marker)
            if existing is None:
                gh_request(api, "POST",
                           f"/repos/{repo}/issues/{pr}/comments", token,
                           {"body": body})
            else:
                gh_request(api, "PATCH",
                           f"/repos/{repo}/issues/comments/{existing['id']}",
                           token, {"body": body})
            print(f"Updated the '{marker_id}' pull request comment.")
            return True
        except urllib.error.HTTPError as exc:
            if attempt < 3 and exc.code in (403, 409, 422, 500, 502, 503):
                time.sleep(0.4 + random.random() * 0.8)
                continue
            print(f"::warning::Could not update the PR comment "
                  f"(HTTP {exc.code}); continuing.")
            return False
        except Exception as exc:
            if attempt < 3:
                time.sleep(0.4 + random.random() * 0.8)
                continue
            print(f"::warning::Could not update the PR comment ({exc}); "
                  f"continuing.")
            return False
    return False
