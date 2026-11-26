"""Decision-threshold sweep: recall against false-positive rate.

The decision threshold cannot be chosen in isolation: it is only meaningful
next to the size of the negative corpus.  This script sweeps the threshold over
the positive actors and the negative actors and reports, for every threshold:

* segment-level recall (and the number of frameworks detected),
* the number of false positives on the negative corpus,
* the false-positive rate with a Wilson interval.

Example
-------
```bash
python -m research.evaluation.threshold_sweep --taus 0.25,0.30,0.35,0.40,0.50
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from . import stats
    from .loaders import (DEFAULT_ACTORS, DEFAULT_NEGATIVES, DEFAULT_TRADEOFF, detected,
                          frameworks_detected, frameworks_of, load_actors, load_json,
                          load_negative_scores)
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation import stats
    from research.evaluation.loaders import (DEFAULT_ACTORS, DEFAULT_NEGATIVES, DEFAULT_TRADEOFF,
                                             detected, frameworks_detected, frameworks_of,
                                             load_actors, load_json, load_negative_scores)

DEFAULT_TAUS = (0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60)


def sweep(actors: list, negatives: list, taus=DEFAULT_TAUS) -> list:
    fws = frameworks_of(actors)
    rows = []
    for tau in taus:
        hit = detected(actors, tau)
        fp = sum(1 for s in negatives if float(s.get("score", 0.0)) >= tau)
        n_neg = len(negatives)
        rows.append({
            "tau": tau,
            "segments_detected": len(hit),
            "segments_total": len(actors),
            "segment_recall": stats.ratio(len(hit), len(actors)),
            "frameworks_detected": len(frameworks_detected(actors, tau)),
            "frameworks_total": len(fws),
            "false_positives": fp,
            "negative_actors": n_neg,
            "fpr": stats.ratio(fp, n_neg),
            "fpr_wilson95": list(stats.wilson(fp, n_neg)) if n_neg else [0.0, 0.0],
        })
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sweep the decision threshold over positive and negative actors.")
    ap.add_argument("--actors", default=str(DEFAULT_ACTORS))
    ap.add_argument("--negatives", default=str(DEFAULT_NEGATIVES))
    ap.add_argument("--taus", default=",".join(str(t) for t in DEFAULT_TAUS))
    ap.add_argument("--archived", default=str(DEFAULT_TRADEOFF),
                    help="archived trade-off artifact, used for a consistency cross-check")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    taus = tuple(float(x) for x in args.taus.split(",") if x.strip())
    actors = load_actors(args.actors)
    negatives = load_negative_scores(args.negatives)
    rows = sweep(actors, negatives, taus)

    print("%-6s %-12s %-10s %-12s %-10s %-24s" % (
        "tau", "segments", "recall", "frameworks", "fpr", "fpr Wilson 95%"))
    for r in rows:
        print("%-6.2f %-12s %-10.4f %-12s %-10.5f [%.5f, %.5f]" % (
            r["tau"], "%d/%d" % (r["segments_detected"], r["segments_total"]),
            r["segment_recall"], "%d/%d" % (r["frameworks_detected"], r["frameworks_total"]),
            r["fpr"], r["fpr_wilson95"][0], r["fpr_wilson95"][1]))

    if args.archived and Path(args.archived).exists():
        arch = load_json(args.archived)
        print("")
        print("cross-check against archived artifact %s" % args.archived)
        for tau_key, a in sorted(arch.get("taus", {}).items(), key=lambda kv: float(kv[0])):
            match = [r for r in rows if abs(r["tau"] - float(tau_key)) < 1e-9]
            if not match:
                continue
            r = match[0]
            fp_ok = (a["fp"] == r["false_positives"])
            fpr_ok = abs(float(a["fpr"]) - r["fpr"]) < 1e-12
            print("  tau=%-5s archived fp=%-4s recomputed fp=%-4s %s" % (
                tau_key, a["fp"], r["false_positives"], "OK" if fp_ok else "MISMATCH"))
            if not fpr_ok:
                print("        archived fpr=%r recomputed fpr=%r MISMATCH" % (a["fpr"], r["fpr"]))

    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
