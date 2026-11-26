"""Leave-one-framework-out generalisation test.

Procedure
---------
For every framework F in the positive corpus:

1. Remove all segments of F.  What remains is the calibration set.
2. Calibrate the decision threshold on the calibration set only: the smallest
   threshold that still detects every remaining framework, that is
   `tau = min over the remaining frameworks of (best segment score of that
   framework)`.
3. Apply that threshold to the held-out framework F and to the negative corpus.

The number of folds is the number of *frameworks*, not the number of segments.
A statement such as "leave-one-out detected 9 of 10" must therefore be
reported as a framework count, and the strength of a generalisation claim
depends on k alone: with all k frameworks detected the one-sided 95% lower
bound is 0.05^(1/k).

Example
-------
```bash
python -m research.evaluation.lofo
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from . import stats
    from .loaders import (DEFAULT_ACTORS, DEFAULT_LOFO, DEFAULT_NEGATIVES, load_actors,
                          load_json, load_negative_scores)
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation import stats
    from research.evaluation.loaders import (DEFAULT_ACTORS, DEFAULT_LOFO, DEFAULT_NEGATIVES,
                                             load_actors, load_json, load_negative_scores)


def best_score_per_framework(actors: list) -> dict:
    out = {}
    for a in actors:
        fw = a.get("fw", "")
        if not fw:
            continue
        s = float(a.get("score", 0.0))
        if fw not in out or s > out[fw]:
            out[fw] = s
    return out


def run_lofo(actors: list, negatives: list) -> list:
    """Return one record per held-out framework."""
    best = best_score_per_framework(actors)
    rows = []
    for holdout in sorted(best):
        calib = {f: s for f, s in best.items() if f != holdout}
        tau = min(calib.values()) if calib else 0.0
        held = [a for a in actors if a.get("fw") == holdout]
        tp = sum(1 for a in held if float(a.get("score", 0.0)) >= tau)
        fp = sum(1 for s in negatives if float(s.get("score", 0.0)) >= tau)
        n_neg = len(negatives)
        rows.append({
            "holdout": holdout,
            "n_test": len(held),
            "tau": tau,
            "tp": tp,
            "recall": stats.ratio(tp, len(held)),
            "fp": fp,
            "n_neg": n_neg,
            "fpr": stats.ratio(fp, n_neg),
            "fp_wilson95": list(stats.wilson(fp, n_neg)) if n_neg else [0.0, 0.0],
            "test_scores": [float(a.get("score", 0.0)) for a in held],
        })
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Leave-one-framework-out generalisation test.")
    ap.add_argument("--actors", default=str(DEFAULT_ACTORS))
    ap.add_argument("--negatives", default=str(DEFAULT_NEGATIVES))
    ap.add_argument("--archived", default=str(DEFAULT_LOFO),
                    help="archived leave-one-out artifact, reported for provenance")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    actors = load_actors(args.actors)
    negatives = load_negative_scores(args.negatives)
    rows = run_lofo(actors, negatives)

    print("%-18s %5s %10s %6s %8s %8s" % ("holdout", "n", "tau", "tp", "recall", "fpr"))
    for r in rows:
        print("%-18s %5d %10.4f %6d %8.3f %8.4f" % (
            r["holdout"], r["n_test"], r["tau"], r["tp"], r["recall"], r["fpr"]))
    det = sum(1 for r in rows if r["tp"] > 0)
    print("frameworks detected when held out: %d/%d" % (det, len(rows)))
    print("one-sided 95%% lower bound for 'all k frameworks detected' (k=%d): %.4f" % (
        len(rows), stats.framework_lower_bound(len(rows))))

    if args.archived and Path(args.archived).exists():
        archived_doc = load_json(args.archived)
        archived = archived_doc.get("results", archived_doc) if isinstance(archived_doc, dict) else archived_doc
        arch_det = sum(1 for r in archived if r.get("tp", 0) > 0)
        print("")
        print("archived artifact %s" % args.archived)
        print("  folds=%d  detected=%d  negative actors=%s" % (
            len(archived), arch_det, archived[0]["n_neg"] if archived else "n/a"))
        print("  note: the archived artifact was produced on an earlier corpus (10 frameworks,")
        print("        %s negative actors); the recomputation above uses the current corpus."
              % (archived[0]["n_neg"] if archived else "n/a"))

    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"folds": rows}, ensure_ascii=False, indent=2, sort_keys=True),
                     encoding="utf-8")
        print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
