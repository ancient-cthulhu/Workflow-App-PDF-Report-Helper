#!/usr/bin/env python3
"""Minimal, dependency-free PDF writer.

Lets the report render a PDF on a CI runner without installing a third-party
library. A scan workflow is a security control, and every package added to its
execution path is a supply-chain dependency. This uses the standard library
only, plus the PDF base-14 fonts every viewer already has, so nothing is
downloaded and no font is embedded.

  Canvas  Page primitives, document assembly, xref and trailer.
  Doc     Flow layout: top-down cursor, page breaks, wrapping, headings,
          tables, cards.

Both use a top-left origin with y increasing downwards, matching how content is
authored; conversion to PDF's bottom-left origin happens at draw time.

Text is encoded as WinAnsi (cp1252). Characters outside it are transliterated
where an ASCII equivalent exists and replaced otherwise, so arbitrary scanner
output can never produce a corrupt file.
"""

from __future__ import annotations

import re
import unicodedata
import zlib
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

__all__ = ["Canvas", "Doc", "PAGE_SIZES", "text_width", "hex_color"]

PAGE_SIZES: Dict[str, Tuple[float, float]] = {
    "a4": (595.28, 841.89),
    "letter": (612.0, 792.0),
}

# Advance widths in 1/1000 em for the PDF base-14 fonts. Needed to measure
# strings so wrapping and column fitting are correct. Written as width -> the
# characters carrying it, which can be checked against a font table by eye;
# a flat array of 224 numbers cannot.
_HELVETICA = {
    191: "'",
    222: "ijl",
    260: "|",
    278: " !,./:;I[\\]ft",
    333: "()-`r",
    334: "{}",
    355: '"',
    389: "*",
    469: "^",
    500: "Jcksvxyz",
    556: "#$0123456789?L_abdeghnopqu",
    584: "+<=>~",
    611: "FTZ",
    667: "&ABEKPSVXY",
    722: "CDHNRUw",
    778: "GOQ",
    833: "Mm",
    889: "%",
    944: "W",
    1015: "@",
}

_HELVETICA_BOLD = {
    238: "'",
    278: " ,./I\\ijl",
    280: "|",
    333: "!()-:;[]`ft",
    389: "*r{}",
    474: "\"",
    500: "z",
    556: "#$0123456789J_aceksvxy",
    584: "+<=>^~",
    611: "?FLTZbdghnopqu",
    667: "EPSVXY",
    722: "&ABCDHKNRU",
    778: "GOQw",
    833: "M",
    889: "%m",
    944: "W",
    975: "@",
}

# Courier is monospaced, so one number covers it.
_COURIER_WIDTH = 600

# Anything not listed above, which in practice means a rare symbol in scanner
# output. Deliberately an over-estimate: measuring a glyph as wider than it is
# wraps text one character early, while under-measuring lets it spill outside
# its column.
_FALLBACK_WIDTH = 611


def _build_widths(groups: Dict[int, str]) -> List[int]:
    """Expand a width -> characters mapping into a 256-entry lookup table.

    Accented Latin letters are not listed: in these fonts they are exactly as
    wide as the letter they decorate, so they are derived. The accented i forms
    are the one exception, being built on a full-width dotless i rather than
    the narrow i.
    """
    table = [_FALLBACK_WIDTH] * 256
    for width, chars in groups.items():
        for ch in chars:
            table[ord(ch)] = width
    for code in range(160, 256):
        ch = bytes([code]).decode("cp1252")
        base = unicodedata.normalize("NFD", ch)[0]
        if base.isascii() and base.isalpha():
            table[code] = 278 if base == "i" else table[ord(base)]
    return table


_WIDTHS: Dict[str, List[int]] = {
    "Helvetica": _build_widths(_HELVETICA),
    "Helvetica-Bold": _build_widths(_HELVETICA_BOLD),
    "Courier": [_COURIER_WIDTH] * 256,
}
# Oblique is a slanted Helvetica and shares its metrics exactly.
_WIDTHS["Helvetica-Oblique"] = _WIDTHS["Helvetica"]

FONT_ALIASES: Dict[str, str] = {
    "r": "Helvetica",
    "b": "Helvetica-Bold",
    "i": "Helvetica-Oblique",
    "m": "Courier",
}
_FONT_RES = {"Helvetica": "F1", "Helvetica-Bold": "F2",
             "Helvetica-Oblique": "F3", "Courier": "F4"}


def _font_name(font: str) -> str:
    return FONT_ALIASES.get(font, font if font in _WIDTHS else "Helvetica")


_TRANSLIT = {
    "\u2018": "'", "\u2019": "'", "\u201a": ",", "\u201b": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"',
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2015": "-", "\u2212": "-",
    "\u2026": "...", "\u00a0": " ", "\u200b": "", "\ufeff": "",
    "\u2192": "->", "\u2190": "<-", "\u21d2": "=>", "\u2264": "<=",
    "\u2265": ">=", "\u2260": "!=", "\u2022": "-", "\u00b7": "-",
    "\u2713": "OK", "\u2714": "OK", "\u2717": "X", "\u2718": "X",
    "\u26a0": "!", "\ufe0f": "", "\u2039": "<", "\u203a": ">",
    "\u00ab": "<<", "\u00bb": ">>", "\u2033": '"', "\u2032": "'",
}
_TRANSLIT_RE = re.compile("|".join(re.escape(k) for k in _TRANSLIT))
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def to_winansi(text: Optional[str]) -> str:
    """Normalize arbitrary text to something cp1252 can represent."""
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    s = _TRANSLIT_RE.sub(lambda m: _TRANSLIT[m.group(0)], s)
    s = _CONTROL_RE.sub(" ", s)
    return s.encode("cp1252", "replace").decode("cp1252")


def _pdf_escape(s: str) -> str:
    """Escape a string for a PDF literal-string token."""
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _pdf_escape_b(s: str) -> bytes:
    return _pdf_escape(s).encode("cp1252", "replace")


def text_width(s: str, font: str = "r", size: float = 9.0) -> float:
    """Advance width of `s` in points at `size`."""
    table = _WIDTHS[_font_name(font)]
    total = 0
    for ch in to_winansi(s):
        code = ord(ch)
        total += table[code] if code < 256 else 500
    return total * size / 1000.0


Color = Any


def hex_color(value: Color) -> Tuple[float, float, float]:
    if isinstance(value, (tuple, list)):
        return (float(value[0]), float(value[1]), float(value[2]))
    s = str(value).lstrip("#")
    if len(s) == 3:
        s = "".join(c * 2 for c in s)
    return (int(s[0:2], 16) / 255.0, int(s[2:4], 16) / 255.0,
            int(s[4:6], 16) / 255.0)


def _fmt(n: float) -> str:
    """Compact fixed-point number for the content stream."""
    return f"{n:.2f}".rstrip("0").rstrip(".") or "0"


def _rgb(value: Color, stroke: bool = False) -> str:
    r, g, b = hex_color(value)
    op = "RG" if stroke else "rg"
    return f"{_fmt(r)} {_fmt(g)} {_fmt(b)} {op}"


class _Page:
    __slots__ = ("ops", "annots")

    def __init__(self) -> None:
        self.ops: List[str] = []
        self.annots: List[Dict[str, Any]] = []


class Canvas:
    """A multi-page PDF with a top-left coordinate origin."""

    def __init__(self, page_size: str = "a4", title: str = "",
                 author: str = "", subject: str = "",
                 creation_date: Optional[str] = None) -> None:
        self.width, self.height = PAGE_SIZES.get(str(page_size).lower(),
                                                 PAGE_SIZES["a4"])
        self.title = title
        self.author = author
        self.subject = subject
        self.creation_date = creation_date
        self.pages: List[_Page] = []
        self.outline: List[Dict[str, Any]] = []
        self.dests: Dict[str, Tuple[int, float]] = {}
        self.new_page()

    def new_page(self) -> int:
        self.pages.append(_Page())
        return len(self.pages) - 1

    @property
    def page_index(self) -> int:
        return len(self.pages) - 1

    @property
    def _cur(self) -> _Page:
        return self.pages[-1]

    def _y(self, y: float) -> float:
        """Top-left y to PDF bottom-left y."""
        return self.height - y

    def rect(self, x: float, y: float, w: float, h: float,
             fill: Optional[Color] = None, stroke: Optional[Color] = None,
             line_width: float = 0.6, radius: float = 0.0) -> None:
        if w <= 0 or h <= 0:
            return
        ops = ["q"]
        if fill is not None:
            ops.append(_rgb(fill))
        if stroke is not None:
            ops.append(_rgb(stroke, stroke=True))
            ops.append(f"{_fmt(line_width)} w")
        if radius > 0:
            ops.append(self._rounded_path(x, y, w, h, radius))
        else:
            ops.append(f"{_fmt(x)} {_fmt(self._y(y + h))} "
                       f"{_fmt(w)} {_fmt(h)} re")
        if fill is not None and stroke is not None:
            ops.append("B")
        elif fill is not None:
            ops.append("f")
        else:
            ops.append("S")
        ops.append("Q")
        self._cur.ops.append(" ".join(ops))

    def _rounded_path(self, x: float, y: float, w: float, h: float,
                      r: float) -> str:
        r = min(r, w / 2.0, h / 2.0)
        k = r * 0.5523
        y0 = self._y(y + h)
        y1 = self._y(y)
        x0, x1 = x, x + w
        p = [f"{_fmt(x0 + r)} {_fmt(y0)} m",
             f"{_fmt(x1 - r)} {_fmt(y0)} l",
             f"{_fmt(x1 - r + k)} {_fmt(y0)} {_fmt(x1)} {_fmt(y0 + r - k)} "
             f"{_fmt(x1)} {_fmt(y0 + r)} c",
             f"{_fmt(x1)} {_fmt(y1 - r)} l",
             f"{_fmt(x1)} {_fmt(y1 - r + k)} {_fmt(x1 - r + k)} {_fmt(y1)} "
             f"{_fmt(x1 - r)} {_fmt(y1)} c",
             f"{_fmt(x0 + r)} {_fmt(y1)} l",
             f"{_fmt(x0 + r - k)} {_fmt(y1)} {_fmt(x0)} {_fmt(y1 - r + k)} "
             f"{_fmt(x0)} {_fmt(y1 - r)} c",
             f"{_fmt(x0)} {_fmt(y0 + r)} l",
             f"{_fmt(x0)} {_fmt(y0 + r - k)} {_fmt(x0 + r - k)} {_fmt(y0)} "
             f"{_fmt(x0 + r)} {_fmt(y0)} c",
             "h"]
        return " ".join(p)

    def line(self, x1: float, y1: float, x2: float, y2: float,
             color: Color = "#000000", width: float = 0.6) -> None:
        self._cur.ops.append(
            f"q {_rgb(color, stroke=True)} {_fmt(width)} w "
            f"{_fmt(x1)} {_fmt(self._y(y1))} m "
            f"{_fmt(x2)} {_fmt(self._y(y2))} l S Q")

    def text(self, x: float, top: float, s: str, font: str = "r",
             size: float = 9.0, color: Color = "#000000",
             char_space: float = 0.0) -> float:
        """Draw one line of text with its cap-top at `top`. Returns the width."""
        s = to_winansi(s)
        if not s:
            return 0.0
        baseline = self._y(top + size * 0.75)
        cs = f"{_fmt(char_space)} Tc " if char_space else ""
        self._cur.ops.append(
            f"q BT {_rgb(color)} /{_FONT_RES[_font_name(font)]} "
            f"{_fmt(size)} Tf {cs}{_fmt(x)} {_fmt(baseline)} Td "
            f"({_pdf_escape(s)}) Tj ET Q")
        return text_width(s, font, size) + char_space * len(s)

    def link(self, x: float, top: float, w: float, h: float, url: str) -> None:
        if not url:
            return
        self._cur.annots.append({"rect": (x, self._y(top + h), x + w,
                                          self._y(top)), "url": url})

    def dest(self, name: str, y: float = 0.0) -> None:
        """Mark the current page and position as a jump target called `name`."""
        self.dests[name] = (self.page_index, self._y(y))

    def link_dest(self, x: float, top: float, w: float, h: float,
                  name: str) -> None:
        """Link a region to a named destination elsewhere in the document.

        Resolved when the file is written, not here, because a target is
        usually declared after the link to it has been drawn: the summary page
        links forward to sections that do not exist yet. An unresolved name is
        dropped rather than producing a dead annotation.
        """
        if not name:
            return
        self._cur.annots.append({"rect": (x, self._y(top + h), x + w,
                                          self._y(top)), "dest": name})

    def bookmark(self, title: str, level: int = 0, y: float = 0.0) -> None:
        self.outline.append({"title": to_winansi(title), "level": max(0, level),
                             "page": self.page_index, "y": self._y(y)})

    def to_bytes(self) -> bytes:
        objs: List[bytes] = []

        def add(body: bytes) -> int:
            objs.append(body)
            return len(objs)

        add(b"")
        add(b"")

        font_refs = {}
        for base, res in sorted(_FONT_RES.items(), key=lambda kv: kv[1]):
            num = add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} "
                      f"/Encoding /WinAnsiEncoding >>".encode("ascii"))
            font_refs[res] = num

        page_refs: List[int] = []
        pending_annots: List[Tuple[int, Dict[str, Any]]] = []
        for page in self.pages:
            stream = "\n".join(page.ops).encode("cp1252", "replace")
            packed = zlib.compress(stream, 9)
            content = add(b"<< /Length " + str(len(packed)).encode()
                          + b" /Filter /FlateDecode >>\nstream\n" + packed
                          + b"\nendstream")
            annot_refs = []
            for a in page.annots:
                num = add(b"")
                annot_refs.append(num)
                pending_annots.append((num, a))
            fonts = " ".join(f"/{res} {num} 0 R"
                             for res, num in sorted(font_refs.items()))
            annots = (" /Annots [" + " ".join(f"{n} 0 R" for n in annot_refs)
                      + "]") if annot_refs else ""
            page_refs.append(add(
                f"<< /Type /Page /Parent 2 0 R /MediaBox "
                f"[0 0 {_fmt(self.width)} {_fmt(self.height)}] "
                f"/Resources << /Font << {fonts} >> >> "
                f"/Contents {content} 0 R{annots} >>".encode("ascii")))

        for num, a in pending_annots:
            x0, y0, x1, y1 = a["rect"]
            rect = f"{_fmt(x0)} {_fmt(y0)} {_fmt(x1)} {_fmt(y1)}".encode()
            head = (b"<< /Type /Annot /Subtype /Link /Rect [" + rect
                    + b"] /Border [0 0 0] /F 4 /A << ")
            if a.get("dest"):
                target = self.dests.get(a["dest"])
                if target is None:
                    objs[num - 1] = b"<< /Type /Annot /Subtype /Link /Rect " \
                                    b"[0 0 0 0] /Border [0 0 0] /F 4 >>"
                    continue
                page_idx, dest_y = target
                action = (f"/S /GoTo /D [{page_refs[page_idx]} 0 R /XYZ 0 "
                          f"{_fmt(dest_y)} 0]").encode("ascii")
            else:
                action = b"/S /URI /URI (" + _pdf_escape_b(a["url"]) + b")"
            objs[num - 1] = head + action + b" >> >>"

        outline_root = self._build_outline(objs, page_refs, add)

        objs[1] = (f"<< /Type /Pages /Kids ["
                   + " ".join(f"{n} 0 R" for n in page_refs)
                   + f"] /Count {len(page_refs)} >>").encode("ascii")
        cat = "<< /Type /Catalog /Pages 2 0 R"
        if outline_root:
            cat += f" /Outlines {outline_root} 0 R /PageMode /UseOutlines"
        cat += " >>"
        objs[0] = cat.encode("ascii")

        info_num = add(self._info_object())

        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (len(objs) + 1)
        for i, body in enumerate(objs, start=1):
            offsets[i] = len(out)
            out += f"{i} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objs) + 1}\n".encode("ascii")
        out += b"0000000000 65535 f \n"
        for i in range(1, len(objs) + 1):
            out += f"{offsets[i]:010d} 00000 n \n".encode("ascii")
        out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R "
                f"/Info {info_num} 0 R >>\nstartxref\n{xref_at}\n"
                f"%%EOF\n").encode("ascii")
        return bytes(out)

    def _info_object(self) -> bytes:
        parts = [b"<<"]
        for key, val in (("Title", self.title), ("Author", self.author),
                         ("Subject", self.subject),
                         ("Producer", "veracode_pdf.py"),
                         ("Creator", "veracode_pdf.py")):
            if val:
                parts.append(b"/" + key.encode() + b" ("
                             + _pdf_escape_b(to_winansi(val)) + b")")
        if self.creation_date:
            parts.append(b"/CreationDate ("
                         + _pdf_escape_b(self.creation_date) + b")")
        parts.append(b">>")
        return b" ".join(parts)

    def _build_outline(self, objs: List[bytes], page_refs: List[int],
                       add: Callable[[bytes], int]) -> Optional[int]:
        """Build a two-level document outline (bookmarks)."""
        if not self.outline:
            return None
        root = add(b"")
        tree: List[Dict[str, Any]] = []
        for item in self.outline:
            if item["level"] == 0 or not tree:
                tree.append({"item": item, "children": []})
            else:
                tree[-1]["children"].append(item)

        def emit(nodes: List[Dict[str, Any]], parent: int) -> Tuple[int, int, int]:
            """Reserve and fill sibling objects. Returns (first, last, count)."""
            if not nodes:
                return (0, 0, 0)
            nums = [add(b"") for _ in nodes]
            total = 0
            for idx, node in enumerate(nodes):
                item = node["item"]
                kids = node.get("children") or []
                child_nodes = [{"item": k, "children": []} for k in kids]
                cfirst, clast, ccount = emit(child_nodes, nums[idx])
                dest = (f"[{page_refs[item['page']]} 0 R /XYZ 0 "
                        f"{_fmt(item['y'])} 0]")
                body = (f"<< /Title ({_pdf_escape(item['title'])}) "
                        f"/Parent {parent} 0 R /Dest {dest}")
                if idx > 0:
                    body += f" /Prev {nums[idx - 1]} 0 R"
                if idx < len(nums) - 1:
                    body += f" /Next {nums[idx + 1]} 0 R"
                if cfirst:
                    body += (f" /First {cfirst} 0 R /Last {clast} 0 R "
                             f"/Count {ccount}")
                body += " >>"
                objs[nums[idx] - 1] = body.encode("cp1252", "replace")
                total += 1 + ccount
            return (nums[0], nums[-1], total)

        first, last, count = emit(tree, root)
        objs[root - 1] = (f"<< /Type /Outlines /First {first} 0 R "
                          f"/Last {last} 0 R /Count {count} >>").encode("ascii")
        return root

    def save(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(self.to_bytes())


def wrap_text(s: str, font: str, size: float, width: float) -> List[str]:
    """Greedy word wrap. Over-long tokens (paths, hashes) are hard-broken."""
    s = to_winansi(s).replace("\t", " ")
    if not s.strip():
        return [""]
    lines: List[str] = []
    for para in s.split("\n"):
        words = para.split(" ")
        cur = ""
        for word in words:
            if not word:
                continue
            trial = word if not cur else cur + " " + word
            if text_width(trial, font, size) <= width:
                cur = trial
                continue
            if cur:
                lines.append(cur)
                cur = ""
            while text_width(word, font, size) > width and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            cur = word
        lines.append(cur)
    return lines or [""]


class Doc:
    """Top-down flow layout with automatic pagination.

    `on_page` is called after every page break with (canvas, page_index) so the
    caller can paint a running header and footer; it must not move the cursor.
    """

    def __init__(self, canvas: Canvas, margin_left: float = 46.0,
                 margin_right: float = 46.0, margin_top: float = 58.0,
                 margin_bottom: float = 52.0,
                 on_page: Optional[Callable[[Canvas, int], None]] = None) -> None:
        self.c = canvas
        self.ml = margin_left
        self.mr = margin_right
        self.mt = margin_top
        self.mb = margin_bottom
        self.on_page = on_page
        self.y = margin_top
        if self.on_page:
            self.on_page(self.c, self.c.page_index)

    @property
    def content_width(self) -> float:
        return self.c.width - self.ml - self.mr

    @property
    def bottom(self) -> float:
        return self.c.height - self.mb

    @property
    def space_left(self) -> float:
        return self.bottom - self.y

    def page_break(self) -> None:
        self.c.new_page()
        self.y = self.mt
        if self.on_page:
            self.on_page(self.c, self.c.page_index)

    def ensure(self, height: float) -> None:
        if self.y + height > self.bottom:
            self.page_break()

    def space(self, height: float) -> None:
        self.y = min(self.y + height, self.bottom)

    def heading(self, text: str, size: float = 14.0, color: Color = "#0F2E4A",
                top_gap: float = 16.0, bottom_gap: float = 7.0,
                rule: bool = True, rule_color: Color = "#D7DEE6",
                bookmark_level: Optional[int] = None) -> None:
        self.ensure(top_gap + size * 1.4 + bottom_gap + 24)
        self.space(top_gap)
        if bookmark_level is not None:
            self.c.bookmark(text, bookmark_level, self.y - 12)
        self.c.text(self.ml, self.y, text, "b", size, color)
        self.y += size * 1.15
        if rule:
            self.y += 4
            self.c.line(self.ml, self.y, self.c.width - self.mr, self.y,
                        rule_color, 0.8)
        self.space(bottom_gap)

    def paragraph(self, text: str, font: str = "r", size: float = 9.0,
                  color: Color = "#33414F", leading: float = 1.42,
                  indent: float = 0.0, bottom_gap: float = 6.0,
                  width: Optional[float] = None) -> None:
        w = (width if width is not None else self.content_width) - indent
        line_h = size * leading
        for line in wrap_text(text, font, size, w):
            self.ensure(line_h)
            self.c.text(self.ml + indent, self.y, line, font, size, color)
            self.y += line_h
        self.space(bottom_gap)

    def rule(self, color: Color = "#E3E9EF", gap: float = 8.0,
             width: float = 0.7) -> None:
        self.ensure(gap * 2)
        self.space(gap)
        self.c.line(self.ml, self.y, self.c.width - self.mr, self.y,
                    color, width)
        self.space(gap)

    def chip(self, x: float, y: float, label: str, fill: Color,
             text_color: Color = "#FFFFFF", size: float = 7.5,
             pad_x: float = 5.0, height: float = 12.5,
             radius: float = 2.5) -> float:
        """Draw a rounded label chip. Returns its width."""
        w = text_width(label, "b", size) + pad_x * 2
        self.c.rect(x, y, w, height, fill=fill, radius=radius)
        self.c.text(x + pad_x, y + (height - size * 0.72) / 2.0 - 0.4,
                    label, "b", size, text_color)
        return w


class Column:
    __slots__ = ("label", "width", "align", "font", "size", "color")

    def __init__(self, label: str, width: float, align: str = "l",
                 font: str = "r", size: float = 8.2,
                 color: Color = "#33414F") -> None:
        self.label = label
        self.width = width
        self.align = align
        self.font = font
        self.size = size
        self.color = color


def _cell(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {"text": "" if value is None else str(value)}


def column_widths(doc: Doc, columns: Sequence[Column]) -> List[float]:
    total = sum(c.width for c in columns) or 1.0
    return [doc.content_width * c.width / total for c in columns]


def _row_layout(columns: Sequence[Column], widths: Sequence[float],
                row: Sequence[Any], pad_x: float, pad_y: float):
    """Wrap one row's cells and return (cells, wrapped, line_height, height)."""
    cells = [_cell(v) for v in row]
    wrapped: List[List[str]] = []
    for col, w, cell in zip(columns, widths, cells):
        wrapped.append(wrap_text(cell.get("text", ""),
                                 cell.get("font", col.font),
                                 cell.get("size", col.size),
                                 w - pad_x * 2))
    line_h = max(c.get("size", col.size)
                 for c, col in zip(cells, columns)) * 1.32
    height = max(len(lines) for lines in wrapped) * line_h + pad_y * 2
    return cells, wrapped, line_h, height


def fit_rows(doc: Doc, columns: Sequence[Column], rows: Sequence[Sequence[Any]],
             available: float, pad_x: float = 6.0, pad_y: float = 5.0,
             header_size: float = 8.0) -> int:
    """How many leading rows, plus the header, fit within `available` points.

    Lets a caller decide whether a table belongs on the current page before it
    commits to drawing a heading above it.
    """
    widths = column_widths(doc, columns)
    used = header_size * 1.35 + pad_y * 2
    count = 0
    for row in rows:
        _cells, _wrapped, _lh, height = _row_layout(columns, widths, row,
                                                    pad_x, pad_y)
        if used + height > available:
            break
        used += height
        count += 1
    return count


def draw_table(doc: Doc, columns: Sequence[Column],
               rows: Sequence[Sequence[Any]],
               header_fill: Color = "#0F2E4A",
               header_color: Color = "#FFFFFF",
               header_size: float = 8.0,
               zebra: Optional[Color] = "#F5F8FA",
               grid: Color = "#E1E8EE",
               pad_x: float = 6.0, pad_y: float = 5.0,
               bottom_gap: float = 8.0,
               repeat_header: bool = True) -> None:
    """Render a table, breaking across pages and repeating the header row."""
    avail = doc.content_width
    widths = column_widths(doc, columns)
    header_h = header_size * 1.35 + pad_y * 2

    def draw_header() -> None:
        doc.c.rect(doc.ml, doc.y, avail, header_h, fill=header_fill)
        x = doc.ml
        for col, w in zip(columns, widths):
            doc.c.text(x + pad_x, doc.y + pad_y + 1, col.label, "b",
                       header_size, header_color)
            x += w
        doc.y += header_h

    doc.ensure(header_h + 26)
    draw_header()

    for r_i, row in enumerate(rows):
        cells, wrapped, line_h, row_h = _row_layout(columns, widths, row,
                                                    pad_x, pad_y)
        if doc.y + row_h > doc.bottom:
            doc.page_break()
            if repeat_header:
                draw_header()

        if zebra and r_i % 2 == 1:
            doc.c.rect(doc.ml, doc.y, avail, row_h, fill=zebra)
        doc.c.line(doc.ml, doc.y + row_h, doc.ml + avail, doc.y + row_h,
                   grid, 0.5)

        x = doc.ml
        for col, w, cell, lines in zip(columns, widths, cells, wrapped):
            font = cell.get("font", col.font)
            size = cell.get("size", col.size)
            color = cell.get("color", col.color)
            align = cell.get("align", col.align)
            ty = doc.y + pad_y
            for line in lines:
                lw = text_width(line, font, size)
                if align == "r":
                    tx = x + w - pad_x - lw
                elif align == "c":
                    tx = x + (w - lw) / 2.0
                else:
                    tx = x + pad_x
                doc.c.text(tx, ty, line, font, size, color)
                ty += line_h
            if cell.get("url"):
                doc.c.link(x + pad_x, doc.y + pad_y, w - pad_x * 2,
                           len(lines) * line_h, cell["url"])
            elif cell.get("dest"):
                doc.c.link_dest(x + pad_x, doc.y + pad_y, w - pad_x * 2,
                                len(lines) * line_h, cell["dest"])
            x += w
        doc.y += row_h

    doc.space(bottom_gap)
