"""Detection effectiveness: segment-level and framework-level recall.

Sampling unit
-------------
The unit of analysis is the behavioural actor (one source address inside one
time window), not the request and not the session.  Two denominators are
reported because they answer different questions:

* **segment level** -- how many observed AI attack segments were detected.
  The uncertainty of this number is bounded with the exact Clopper-Pearson
  interval and with the Jeffreys interval; both ignore clustering and are
  therefore narrower than they should be.
* **framework level** -- how many distinct attack frameworks were detected at
  least once.  This is the quantity that supports a generalisation claim, and
  its uncertainty is driven by the number of frameworks k, not by the number
  of segments: with all k frameworks detected the one-sided 95% lower bound is
  0.05^(1/k).

False positives are counted on independent negative actors with a Wilson
interval; see `false_positive_eval.py` for the long form.

Example
-------
```bash
python -m research.evaluation.evaluate_detection --threshold 0.35
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from . import stats
    from .loaders import (DEFAULT_ACTORS, DEFAULT_NEGATIVES, detected, frameworks_detected,
                          frameworks_of, load_actors, load_negative_scores)
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation import stats
    from research.evaluation.loaders import (DEFAULT_ACTORS, DEFAULT_NEGATIVES, detected,
                                             frameworks_detected, frameworks_of, load_actors,
                                             load_negative_scores)

DEFAULT_THRESHOLD = 0.35


def evaluate(actors: list, negatives: list, threshold: float = DEFAULT_THRESHOLD) -> dict:
    """Compute the recall and false-positive summary at one threshold."""
    n_seg = len(actors)
    hit_seg = detected(actors, threshold)

    fws = frameworks_of(actors)
    hit_fw = frameworks_detected(actors, threshold)
    k_fw = len(hit_fw)

    n_neg = len(negatives)
    fp = sum(1 for s in negatives if float(s.get("score", 0.0)) >= threshold)

    cp_seg = stats.clopper_pearson(len(hit_seg), n_seg)
    je_seg = stats.jeffreys(len(hit_seg), n_seg)
    cp_fw = stats.clopper_pearson(k_fw, len(fws))
    je_fw = stats.jeffreys(k_fw, len(fws))
    wil = stats.wilson(fp, n_neg) if n_neg else (0.0, 0.0)

    return {
        "threshold": threshold,
        "segment_level": {
            "detected": len(hit_seg), "total": n_seg,
            "recall": stats.ratio(len(hit_seg), n_seg),
            "clopper_pearson_95": list(cp_seg),
            "jeffreys_95": list(je_seg),
            "missed": [{"framework": a.get("fw"), "capture": a.get("lab"), "score": a.get("score")}
                       for a in actors if float(a.get("score", 0.0)) < threshold],
        },
        "framework_level": {
            "detected": k_fw, "total": len(fws),
            "recall": stats.ratio(k_fw, len(fws)),
            "clopper_pearson_95": list(cp_fw),
            "jeffreys_95": list(je_fw),
            "one_sided_95_lower_bound": stats.framework_lower_bound(len(fws)),
            "frameworks": fws,
            "detected_frameworks": hit_fw,
        },
        "false_positive": {
            "negative_actors": n_neg,
            "false_positives": fp,
            "fpr": stats.ratio(fp, n_neg),
            "wilson_95": list(wil),
            "rule_of_three_upper_bound": stats.rule_of_three(n_neg),
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Segment-level and framework-level recall with exact intervals.")
    ap.add_argument("--actors", default=str(DEFAULT_ACTORS),
                    help="actor artifact (JSON) or directory of actor score files")
    ap.add_argument("--negatives", default=str(DEFAULT_NEGATIVES),
                    help="negative actor features (JSONL) or directory")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    actors = load_actors(args.actors)
    negatives = load_negative_scores(args.negatives)
    rep = evaluate(actors, negatives, args.threshold)

    seg = rep["segment_level"]
    fw = rep["framework_level"]
    fp = rep["false_positive"]
    print("threshold = %.2f" % rep["threshold"])
    print("segment level   : %d/%d = %.4f  CP95 [%.4f, %.4f]  Jeffreys95 [%.4f, %.4f]" % (
        seg["detected"], seg["total"], seg["recall"],
        seg["clopper_pearson_95"][0], seg["clopper_pearson_95"][1],
        seg["jeffreys_95"][0], seg["jeffreys_95"][1]))
    print("framework level : %d/%d = %.4f  one-sided 95%% lower bound = %.4f" % (
        fw["detected"], fw["total"], fw["recall"], fw["one_sided_95_lower_bound"]))
    print("false positives : %d/%d = %.4f  Wilson95 [%.4f, %.4f]" % (
        fp["false_positives"], fp["negative_actors"], fp["fpr"],
        fp["wilson_95"][0], fp["wilson_95"][1]))
    for m in seg["missed"]:
        print("  missed: %s / %s  score=%.4f" % (m["framework"], m["capture"], m["score"]))
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
