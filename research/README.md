# Research pipeline

Reproducible code for the traffic-signature study of AI penetration-testing
agents.  Everything in this directory runs from the repository root or from
this directory, reads only files that ship with the repository, and writes
nothing outside it.

## Layout

```
research/
  engine/       the detection engine that produced the study numbers
  pipeline/     request stream -> actors -> features -> attribution score
  evaluation/   recall, false-positive, ablation and leave-one-out statistics
  ci/           the checks invoked by the GitHub Actions workflow
  tests/        unit tests for the pipeline
```

* `engine/` is a copy of the detection engine, so that the released
  repository can reproduce the study without any external dependency.  See
  `engine/PROVENANCE.md` for the two documented differences from the
  original and for the verification that was run on them.
* `pipeline/` turns a request stream into behavioural actors and scores them.
* `evaluation/` recomputes every published statistic from the artifacts in
  `data/`.
* `ci/` contains the checks that the workflow runs.

## Requirements

Python 3.11 or later.  The pipeline itself uses the standard library only, so
it runs with nothing installed; the pinned packages in `requirements.txt` are
used by the optional SciPy cross-check of the interval estimators and by the
test suite.

```
bash
cd research
pip install -r requirements.txt
```

## Commands

All commands below are run from the repository root unless stated otherwise.
The expected runtimes were measured on a single core of an ordinary x86-64
workstation.

### 1. Score the published AI agent captures (about 65 s)

```
bash
python -m research.pipeline.score_actor --input data/positive --out out/actor
```

Every capture directory below `data/positive/` is segmented into behavioural
actors (one source address inside one session), the feature families F1..F11
are extracted for each actor, and the attribution score is computed.  One JSONL
file per capture is written into the output directory.

### 2. Recall and false positives (about 1 s each)

```
bash
python -m research.evaluation.evaluate_detection --threshold 0.35
python -m research.evaluation.false_positive_eval --threshold 0.35
python -m research.evaluation.lofo
python -m research.evaluation.family_ablation --threshold 0.35
python -m research.evaluation.threshold_sweep
```

* `evaluate_detection.py` reports the segment-level recall (13 of 15 segments
  at the threshold 0.35) with the exact Clopper-Pearson and the Jeffreys
  interval, and the framework-level recall (10 of 12 frameworks) with the
  one-sided 95% lower bound 0.05^(1/k).
* `false_positive_eval.py` reports the false-positive rate over the 1,582
  real attacker actors with a Wilson interval and the rule-of-three bound, and
  separately the rate over the 6 scanner container actors.
* `lofo.py` runs the leave-one-framework-out test: for every held-out
  framework the threshold is calibrated on the remaining frameworks only.
* `family_ablation.py` computes the exact recall ceiling when one feature
  family is missing from the logs.
* `threshold_sweep.py` prints the recall against false-positive trade-off and
  cross-checks it with the archived artifact.

### 3. The CI checks (about 3 s in total)

```
bash
# signature lint and platform consistency, for both licensed subsets
python -m research.ci.check_signatures \
    --rules signatures/rules.json --platform-dir signatures \
    --agpl-rules signatures/agpl/rules-agpl.json --agpl-dir signatures/agpl

# self-tests: benign traffic, a known tier-1 pattern, the shipped scanner traffic
python -m research.ci.selftest_rules

# every headline number of the repository README, recomputed from the artifacts
python -m research.ci.check_headline_numbers --readme README.md
```

### 4. Tests (about 2 s)

```
bash
python -m pytest research/tests -q
```

## What the checks enforce

| Check | What fails the build |
|---|---|
| `check_signatures.py` | a rule that does not compile as a Python regular expression, a deployed expression that contains `\s` (Lucene and KQL have no `\s` operator), a platform file whose rule count does not match the rule set, an empty platform rule |
| `selftest_rules.py` | a tier-1 rule that fires on a synthetic benign browser request, a tier-1 rule that does not fire on a request carrying its own literal, a tier-1 rule that fires on the published scanner captures |
| `check_headline_numbers.py` | any number in the repository README that the shipped artifacts do not reproduce |

The platform-count invariant is recomputed from the rule set on every run:
Elasticsearch, Splunk and Suricata carry every non-retired rule that an HTTP
access log can show (fields `user_agent`, `uri`, `body`, `header`), and
Sigma carries the User-Agent rules only, because the Sigma webproxy schema
models the request as an image with a single `UserAgent` field.

## Measured versus inherited numbers

* The headline numbers are **recomputed** from the artifacts in `data/` and
  `signatures/` by `check_headline_numbers.py`.
* Recomputing the attribution score from the published captures reproduces the
  recorded score exactly for 10 of the 15 captures.  For the other five the
  published capture is the complete, pseudonymised capture, while the recorded
  score was computed on the agent-labelled subset of the original capture, so
  the recomputed value differs.  The published numbers therefore come from
  `data/aggregate/framework_detection.json`, which is the artifact the study
  produced, and the pipeline demonstrates that the computation itself is
  reproducible.
* Two families cannot be computed from a request-only capture (F1 needs the
  response headers or body, F2 needs a response side channel).  They are
  reported as unavailable rather than as zero.
