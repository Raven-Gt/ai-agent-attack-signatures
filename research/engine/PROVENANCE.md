# Provenance of the vendored detection engine

These modules are a copy of the detection engine that produced every number
reported in the study, so that the released repository can reproduce the
results without any dependency on the original working tree.

| Module | Role |
|---|---|
| `capture.py` | request event model and access-log reader (`Request`, `Egress`) |
| `config.py` | feature-family switches, thresholds, noise-filter settings |
| `segment.py` | noise removal, actor and session segmentation, sliding windows |
| `features.py` | feature families F1..F11 |
| `evidence.py` | evidence rules E1..E15 and the noisy-OR score |
| `ioc_match.py` | the single authoritative IOC match and deploy-regex implementation |
| `ground_truth.py` | actor labels, used for evaluation only |
| `evaluate.py` | confusion matrix, ROC and PR, Wilson interval, cluster bootstrap |
| `frameworks.py` | lab to framework mapping used by the study |

The released pipeline calls `capture.py`, `config.py`, `segment.py`,
`features.py`, `evidence.py` and `ioc_match.py`.  `ground_truth.py`,
`frameworks.py` and `evaluate.py` are kept for completeness of the copy and
are not called by the released scripts.

## Differences from the original

Two regions differ from the original copy.  No scoring logic, threshold,
feature definition or rule definition was changed.

1. **`config.py` - the lab registry.**  The original hard-coded absolute
   paths to an experimental lab share.  The released repository must not
   reference locations outside itself, so the registry is now read from an
   optional `labs.json` next to the module (empty when the file is absent).
   Callers pass capture files explicitly.

2. **`features.py` - the burst-cluster scan.**  The original computed the
   largest number of requests inside a window of fixed width with a quadratic
   scan, which makes the extraction of a capture with tens of thousands of
   requests take minutes.  The released copy computes the same quantity with a
   sliding two-pointer window.  The two are equivalent: both compute the
   maximum number of requests contained in any window of that width, because
   every window of the width w is contained in a window anchored at its left
   end and in one anchored at its right end.  The equivalence was checked on
   300 randomised timestamp series with zero mismatches.

## Verification

* The engine imports cleanly under `python -W error::SyntaxWarning`.
* No file in this directory contains characters outside ASCII.
* The attribution score of the published captures is reproduced by
  `research/pipeline/score_actor.py`; the comparison against the recorded
  scores is documented in `research/README.md`.
