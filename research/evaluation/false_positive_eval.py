"""False-positive evaluation on the negative corpus.

Counting unit
-------------
The false-positive rate is counted over *independent behavioural actors*, not
over requests.  A request-level denominator would understate the rate by the
average number of requests per actor.

Three estimators are reported:

* the point estimate with a Wilson score interval,
* the rule of three: with zero false positives in n actors the 95% upper bound
  on the rate is 3/n, which is the strongest statement a zero-event sample
  supports,
* a stratification of the negative corpus, because the false positives
  concentrate in the traffic that does not adapt to responses.

Two negative corpora are covered:

* the real internet attackers segmented by source address and 10 minute window
  (`data/features/actor_features.jsonl`),
* the scanner containers (`data/negative/_index.json`), which measure the
  known blind spot of passive HTTP detection.

Example
-------
```bash
python -m research.evaluation.false_positive_eval --threshold 0.35
```
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

try:
    from . import stats
    from .loaders import (DEFAULT_NEGATIVE_INDEX, DEFAULT_NEGATIVES, load_negative_scores,
                          load_scanner_actors)
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation import stats
    from research.evaluation.loaders import (DEFAULT_NEGATIVE_INDEX, DEFAULT_NEGATIVES,
                                             load_negative_scores, load_scanner_actors)

DEFAULT_THRESHOLD = 0.35


def _block(scores, threshold):
    m = len(scores)
    k = sum(1 for x in scores if x >= threshold)
    return {
        "actors": m, "false_positives": k, "fpr": stats.ratio(k, m),
        "wilson_95": list(stats.wilson(k, m)) if m else [0.0, 0.0],
        "rule_of_three_upper_bound": stats.rule_of_three(m),
    }


def evaluate(negatives: list, scanners: list, threshold: float = DEFAULT_THRESHOLD) -> dict:
    scores = [float(s.get("score", 0.0)) for s in negatives]
    by_class = {}
    for s in negatives:
        by_class.setdefault(s.get("cls", "unknown"), []).append(float(s.get("score", 0.0)))
    return {
        "threshold": threshold,
        "real_attackers": _block(scores, threshold),
        "scanner_actors": _block([float(s.get("score", 0.0)) for s in scanners], threshold),
        "by_class": {k: _block(v, threshold) for k, v in sorted(by_class.items())},
        "max_score": max(scores) if scores else 0.0,
        "actors_needed_for_rule_of_three": {
            "1 percent": int(math.ceil(3 / 0.01)),
            "0.1 percent": int(math.ceil(3 / 0.001)),
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="False-positive rate with Wilson interval and rule of three.")
    ap.add_argument("--features", default=str(DEFAULT_NEGATIVES),
                    help="negative actor features (JSONL) or the data/features directory")
    ap.add_argument("--scanner-index", default=str(DEFAULT_NEGATIVE_INDEX))
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    negatives = load_negative_scores(args.features)
    scanners = load_scanner_actors(args.scanner_index)
    rep = evaluate(negatives, scanners, args.threshold)

    for label in ("real_attackers", "scanner_actors"):
        b = rep[label]
        print("%-16s actors=%-6d fp=%-4d fpr=%.5f (%.2f%%) Wilson95 [%.5f, %.5f]" % (
            label, b["actors"], b["false_positives"], b["fpr"], 100.0 * b["fpr"],
            b["wilson_95"][0], b["wilson_95"][1]))
    print("highest negative actor score : %.4f" % rep["max_score"])
    for k, v in rep["by_class"].items():
        print("  class %-10s actors=%-6d fp=%-4d fpr=%.5f" % (
            k, v["actors"], v["false_positives"], v["fpr"]))
    print("independent negative actors needed for a rule-of-three bound: %s" % rep["actors_needed_for_rule_of_three"])
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
