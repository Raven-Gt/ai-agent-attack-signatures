# -*- coding: utf-8 -*-
"""Verification pass over the generated figures.

Checks, for every PNG:
  * the file exists and is not blank (ink coverage and pixel variance)
  * the rendered width meets the minimum (1400 px wide / 900 px tall)
  * the vector sibling (PDF + SVG) exists and is not empty
  * every string that reaches the canvas is ASCII (checked on the SVG text)

Run:  python figures/verify_figures.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image

FIG_DIR = Path(__file__).resolve().parent
VEC_DIR = FIG_DIR / "vector"

WIDE_MIN = 1400
TALL_MIN = 900
TEXT_RE = re.compile(r"<text[^>]*>(.*?)</text>", re.S)


def main() -> int:
    problems = []
    rows = []
    for png in sorted(FIG_DIR.glob("fig*.png")):
        name = png.stem
        with Image.open(png) as im:
            w, h = im.size
            rgb = im.convert("L")
            px = rgb.getdata()
            total = w * h
            ink = sum(1 for v in px if v < 245)
            extrema = rgb.getextrema()
        need = WIDE_MIN if w >= h else TALL_MIN
        ok_blank = (ink / total) < 0.005 or extrema[0] > 250
        ok_size = w >= need
        pdf = VEC_DIR / (name + ".pdf")
        svg = VEC_DIR / (name + ".svg")
        ok_vec = pdf.exists() and pdf.stat().st_size > 1000 and svg.exists() and svg.stat().st_size > 1000
        non_ascii = []
        if svg.exists():
            for chunk in TEXT_RE.findall(svg.read_text(encoding="utf-8", errors="replace")):
                for ch in chunk:
                    if ord(ch) > 127:
                        non_ascii.append(ch)
        rows.append((name, w, h, ink / total * 100.0, need,
                     "blank!" if ok_blank else "ok",
                     "small" if not ok_size else "ok",
                     "missing" if not ok_vec else "ok",
                     "".join(sorted(set(non_ascii))) or "-"))
        if ok_blank:
            problems.append("%s looks blank" % name)
        if not ok_size:
            problems.append("%s is %dx%d, below the %d px minimum" % (name, w, h, need))
        if not ok_vec:
            problems.append("%s has no vector sibling" % name)
        if non_ascii:
            problems.append("%s contains non-ASCII characters: %s" % (name, "".join(sorted(set(non_ascii)))))
    print("%-44s %6s %6s %8s %6s %-7s %-6s %-8s %s" %
          ("figure", "width", "height", "ink %", "min px", "content", "size", "vector", "non-ascii"))
    for r in rows:
        print("%-44s %6d %6d %7.2f%% %6d %-7s %-6s %-8s %s" % r)
    print("")
    if problems:
        print("FAILED:")
        for p in problems:
            print("  - " + p)
        return 1
    print("OK: %d figures - none blank, all within the size budget, all with vector siblings, "
          "all English only" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
