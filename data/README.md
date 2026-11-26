# Released dataset

This directory is the data release that accompanies the study on traffic-level detection of
AI-agent-driven attack traffic. It is organised so that a reader can move from raw evidence to
derived tables without needing any of the project's internal working files.

| Path | What it holds |
|---|---|
| `DATASET_CARD.md` | The dataset card: provenance, licence, collection process, intended and out-of-scope use, limitations, ethics notes, and the full file inventory with checksums. |
| `positive/` | 15 actor captures of AI penetration-testing agent traffic, one directory per capture, each with `access.jsonl` (raw request records) and `meta.json`. 12 frameworks, 211,547 request records. |
| `negative/` | 6 actor captures of real scanner traffic against the same target, in the same format. 999 request records. |
| `features/` | Pseudonymised feature vectors for the 1,582 real-attacker actors derived from a 30-day WAF audit log, as `actor_features.jsonl`, `actor_features.csv` and `feature_dictionary.json`. |
| `aggregate/` | Summary tables: per-framework detection results, threshold/false-positive trade-off, leave-one-framework-out results, feature-family ablation bounds, framework coverage matrix, rule validation counts, negative-set summary, and the checksum manifest. |

## Where to start

* For the headline numbers and their exact definitions, read `DATASET_CARD.md`.
* For the raw evidence, open any capture under `positive/` or `negative/`.
* For modelling or threshold work, use `features/actor_features.csv`.

## Reading order for a first-time reader

1. `DATASET_CARD.md` section 5 (collection process) and section 11 (what the data supports).
2. `aggregate/framework_detection_summary.csv` - one row per framework.
3. `aggregate/threshold_fpr_tradeoff.csv` - the recall/false-positive trade-off.
4. `negative/README.md` - the boundary case that limits every conclusion in the release.

## Note on addresses

No Internet source address and no raw third-party request record is published anywhere under
`data/`. The only addresses present are the evaluation environment's own loopback and private
container addresses, and the RFC 2544 benchmark address used to give the target a reachable
non-private address. The 1,582 real-attacker actors appear only under pseudonymous identifiers;
see `features/README.md` for the construction and its residual re-identification caveat.
