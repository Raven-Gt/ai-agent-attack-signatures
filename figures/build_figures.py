# -*- coding: utf-8 -*-
"""Build every figure of the paper figure set.

Usage:
    python figures/build_figures.py            # all figures
    python figures/build_figures.py 1 4 7      # only the listed figures

Outputs:
    figures/figNN_*.png        raster, for the README
    figures/vector/figNN_*.pdf  vector, for the paper
    figures/vector/figNN_*.svg  vector, for the paper
    figures/CAPTIONS.md         numbered captions with the headline number
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from figlib import apply_style  # noqa: E402
import figures_a  # noqa: E402
import figures_b  # noqa: E402

BUILDERS = [
    figures_a.figure1, figures_a.figure2, figures_a.figure3, figures_a.figure4,
    figures_a.figure5, figures_a.figure6, figures_b.figure7, figures_b.figure8,
    figures_b.figure9, figures_b.figure10, figures_b.figure11, figures_b.figure12,
]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    apply_style()
    wanted = [int(a) for a in argv] if argv else None
    results = []
    for i, fn in enumerate(BUILDERS, start=1):
        if wanted and i not in wanted:
            continue
        res = fn()
        w, h = res["px"]
        print("[ok] %-46s %5d x %-5d px" % (res["name"], w, h))
        results.append(res)
    return results


if __name__ == "__main__":
    main()
