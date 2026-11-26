# -*- coding: utf-8 -*-
"""Shared style + data loading for the paper figures of ai-agent-attack-signatures.

Design rules (publication look):
  * matplotlib only, no seaborn
  * colour-blind safe palette that also survives greyscale printing
  * no top/right spines, horizontal gridlines only
  * label fonts >= 10 pt, axis titles >= 12 pt, figure titles >= 13 pt bold
  * English only - every label that reaches a figure is asserted ASCII

The module also exposes the loaders for every artifact the figures are built
from, so that every number in a figure can be traced back to a shipped file.
"""
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Patch

REPO_ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = REPO_ROOT / "figures"
VEC_DIR = FIG_DIR / "vector"
DATA = REPO_ROOT / "data"
AGG = DATA / "aggregate"
POS = DATA / "positive"
NEG = DATA / "negative"

# ----------------------------------------------------------------- palette ---
BLUE = "#2E5EAA"     # primary series
RED = "#D1495B"      # detection / alert
TEAL = "#2A9D8F"     # positive / clean
AMBER = "#E9C46A"    # secondary / warning
GREY = "#6C757D"     # neutral
INK = "#1F2933"      # text
MUTED = "#9AA5B1"    # faint structure

# greyscale-safe ladder: the four accents differ strongly in luminance
# (BLUE 0.36, RED 0.45, TEAL 0.54, AMBER 0.80), so they stay separable when
# printed in greyscale.
PALETTE = [BLUE, RED, TEAL, AMBER, GREY]

DPI = 150
WIDE_MIN_PX = 1400
TALL_MIN_PX = 900


def apply_style() -> None:
    plt.rcParams.update({
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.labelsize": 12,
        "axes.labelcolor": INK,
        "axes.edgecolor": MUTED,
        "axes.linewidth": 0.9,
        "axes.grid": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "text.color": INK,
        "xtick.color": INK,
        "ytick.color": INK,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "legend.fontsize": 10,
        "legend.frameon": False,
        "legend.handlelength": 1.6,
        "figure.titlesize": 15,
        "figure.titleweight": "bold",
        "lines.linewidth": 2.0,
        "lines.markersize": 6,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })


def check_ascii(text: str, where: str) -> str:
    """Every string that reaches a figure must be English/ASCII."""
    bad = [c for c in str(text) if ord(c) > 127]
    if bad:
        raise ValueError("non-ASCII characters in %s: %r" % (where, "".join(sorted(set(bad)))))
    return text


def save(fig, name: str, width_in: float, height_in: float) -> dict:
    """Write PNG (README) + PDF/SVG (paper) and verify the PNG size budget."""
    VEC_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    png = FIG_DIR / (name + ".png")
    fig.savefig(png, dpi=DPI, bbox_inches="tight", facecolor="white")
    fig.savefig(VEC_DIR / (name + ".pdf"), bbox_inches="tight", facecolor="white")
    fig.savefig(VEC_DIR / (name + ".svg"), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    w_px, h_px = png_size(png)
    need = WIDE_MIN_PX if w_px >= h_px else TALL_MIN_PX
    if w_px < need:
        raise ValueError("%s is %dx%d px, below the %d px minimum" % (name, w_px, h_px, need))
    return {"name": name, "png": str(png), "px": (w_px, h_px)}


def png_size(path: Path) -> tuple:
    from PIL import Image  # pillow is available for verification only
    with Image.open(path) as im:
        return im.size


# ------------------------------------------------------------------ loaders ---
def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path):
    out = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple:
    """Wilson score interval (same implementation as research/evaluation/stats.py)."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def framework_lower_bound(k: int, alpha: float = 0.05) -> float:
    return float(alpha ** (1.0 / k)) if k else 0.0


# ---------------------------------------------------------- domain helpers ---
UUID_RE = None
LONGNUM_RE = None
HASH_RE = None
EMAIL_RE = None


def _init_regex():
    global UUID_RE, LONGNUM_RE, HASH_RE, EMAIL_RE
    import re
    UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    LONGNUM_RE = re.compile(r"\d{3,}")
    HASH_RE = re.compile(r"\b[0-9a-f]{16,}\b")
    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def normalize_path(uri: str) -> str:
    """Same endpoint templating as research/engine/segment.py."""
    _init_regex()
    p = (uri or "").split("?")[0]
    p = UUID_RE.sub("{id}", p)
    p = HASH_RE.sub("{id}", p)
    p = EMAIL_RE.sub("{email}", p)
    p = LONGNUM_RE.sub("{id}", p)
    return p


def actor_stats(records, agent_filter=None):
    """Request rate (req/min) and endpoint breadth for one actor."""
    n = len(records)
    if n == 0:
        return {"n": 0, "duration_s": 0.0, "rpm": 0.0, "templates": 0, "families": 0}
    ts = [r["ts"] for r in records]
    from datetime import datetime
    def parse(t):
        return datetime.fromisoformat(t).timestamp()
    t0, t1 = min(map(parse, ts)), max(map(parse, ts))
    dur = max(1e-9, t1 - t0)
    tmpl = [normalize_path(r.get("uri", "")) for r in records]
    fams = {("/" + [s for s in t.split("/") if s][0]) if [s for s in t.split("/") if s] else "/" for t in tmpl}
    return {"n": n, "duration_s": dur, "rpm": n / (dur / 60.0),
            "templates": len(set(tmpl)), "families": len(fams)}
