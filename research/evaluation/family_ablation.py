"""Feature-family ablation: exact recall ceilings.

Question
--------
If one feature family is not available in a deployment's logs (for example
the feedback-adaptivity family, which needs response-aware logging), what is
the *exact* upper bound on recall?

Method
------
For every actor the study recorded which evidence rules fired and with which
weight, grouped by feature family.  Removing a family means removing exactly
those rules, so the remaining score is recomputed as
`1 - prod(1 - w)` over the surviving families.  The resulting share of actors
that still reach the decision threshold is a deterministic ceiling, not an
estimate.

Note on the base rate
---------------------
The ceiling is computed on the noisy-OR combination of the fired rules, that
is without the reverse-evidence veto (E14, E15) that caps the score of a
dictionary enumerator at 0.25.  The base recall of this ablation is therefore
one actor higher than the headline segment recall, which is the number the
decision pipeline reports.

Example
-------
```bash
python -m research.evaluation.family_ablation --threshold 0.35
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .loaders import DEFAULT_ACTORS, load_actors
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation.loaders import DEFAULT_ACTORS, load_actors

DEFAULT_THRESHOLD = 0.35


def _score(weights: dict, drop: str = None) -> float:
    prod = 1.0
    for fam, w in weights.items():
        if drop is not None and fam == drop:
            continue
        prod *= (1.0 - float(w))
    return 1.0 - prod


def ablation(actors: list, threshold: float = DEFAULT_THRESHOLD) -> dict:
    families = sorted({f for a in actors for f in (a.get("weights") or {})})
    base = sum(1 for a in actors if _score(a.get("weights") or {}) >= threshold)
    per_family = {}
    for fam in families:
        kept = sum(1 for a in actors if _score(a.get("weights") or {}, drop=fam) >= threshold)
        per_family[fam] = {
            "detected": kept,
            "total": len(actors),
            "upper_recall": (kept / len(actors)) if actors else 0.0,
            "lossless": kept == base,
        }
    return {
        "threshold": threshold,
        "families": families,
        "base_recall": (base / len(actors)) if actors else 0.0,
        "base_detected": base,
        "total": len(actors),
        "per_family_upper_recall": {f: per_family[f]["upper_recall"] for f in families},
        "per_family": per_family,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Exact recall ceilings when one feature family is missing.")
    ap.add_argument("--actors", default=str(DEFAULT_ACTORS))
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    actors = load_actors(args.actors)
    rep = ablation(actors, args.threshold)
    print("base recall (all families available, reverse evidence veto not applied): %.4f (%d/%d)" % (
        rep["base_recall"], rep["base_detected"], rep["total"]))
    for fam in rep["families"]:
        d = rep["per_family"][fam]
        print("  without %-5s -> recall ceiling %.4f (%d/%d) %s" % (
            fam, d["upper_recall"], d["detected"], d["total"],
            "lossless" if d["lossless"] else "lossy"))
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
