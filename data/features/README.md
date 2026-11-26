# Real-attacker actor feature vectors

This directory holds **pseudonymised feature vectors for the 1,582 real-attacker actors** used to
measure the false-positive rate of the behaviour-level AI-attribution detector.

The vectors are *derived* data: they contain no request content of any kind and no network address
of any kind.

## Files

| File | Shape | Description |
|---|---|---|
| `actor_features.jsonl` | 1,582 lines, one JSON object per actor | Full record per actor: pseudonymous id, actor class, request count, time window, AI score, fired rule ids, and the 103 extracted feature values. |
| `actor_features.csv` | 1,582 rows x 112 columns | The same data flattened: 9 metadata columns followed by the 103 feature columns in canonical order. |
| `feature_dictionary.json` | 103 entries | For every feature: the family it belongs to and a one-line description of what it measures. |

## Pseudonymisation

* The actor identifier is `actor_` followed by the first 12 hexadecimal characters of the
  SHA-256 digest of the actor's source address, taken over the UTF-8 bytes of the address string.
  The mapping is deterministic and stable, so the same actor keeps the same identifier across
  releases and across recomputations.
* The source address itself is **not** present in any released file, in any form: not as a
  column, not inside a URI, not inside a user-agent string, not in a metadata field.
* No request header, request body, query string, path, response code sequence or timestamp of an
  individual request is released. Only per-actor aggregates and per-actor feature values are.
* The only free-text field in the released CSV is the semicolon-joined list of fired rule ids
  (`E1`, `E3`, ...), which is a detector artefact, not traffic content.
* The SHA-256 construction is unkeyed, as specified for this release. An adversary who already
  holds the source WAF log could confirm a candidate address by recomputing its digest, and the
  IPv4 address space is small enough to be enumerated. A future release that must resist
  re-identification should replace this with a keyed digest (HMAC) under a salt that is not
  published alongside the data.

## Actor class

Two classes are present, following the operational definition used throughout the evaluation:

* `browser` (1,378 actors) - the actor's user-agent blob classifies as a browser.
* `tool` (204 actors) - the actor's user-agent blob classifies as a command-line tool.

Actors whose user-agent blob classifies as a crawler or as absent are **not** part of this
directory. They are a separate population whose false-positive rate is markedly higher, and
mixing them into the released set would misstate the measured rate.

## How the vectors were produced

1. The source population is a 30-day WAF audit log holding 151,011 attack transactions.
2. Requests are grouped into actors by source address; actors with fewer than 5 requests are
   discarded (the minimum actor size used by the evaluation).
3. The 103 features are extracted from each actor's request list with the project's feature
   extractor, using the same feature names, the same family definitions and the same thresholds
   as the published detector.
4. The actor's AI score and fired rule ids are read from the evaluation artifact that is the
   declared source of truth for scores. The scoring pipeline was re-run independently over the
   same inputs and reproduced every actor's score and fired-rule set exactly (2,794 actors,
   0 mismatches), so the released vectors and the released scores are mutually consistent.

## Field reference (JSONL)

| Field | Type | Meaning |
|---|---|---|
| `actor_id` | string | Pseudonymous actor identifier. |
| `actor_class` | string | `browser` or `tool`. |
| `request_count` | integer | Number of requests attributed to the actor. |
| `time_window.start` / `.end` | ISO-8601 UTC | First and last request of the actor. |
| `time_window.duration_s` | number | Elapsed seconds between them. |
| `ai_score` | number | Detector score in [0, 1]; noisy-OR combination of the fired rules. |
| `fired_rules` | array of string | Detector rule ids that fired for this actor. |
| `fired_rule_count` | integer | Length of `fired_rules`. |
| `detected_at_threshold` | boolean | Whether `ai_score` reaches the decision threshold of 0.35. |
| `features` | object | The 103 extracted feature values, all numeric. |

## Known caveats

* `f8_egress_*` (8 features) are structurally zero for every actor in this directory: the source
  WAF log records inbound transactions only, so no outbound attempt can be attributed to an actor.
  These zeros are a property of the instrumentation, not an observation about the actors.
* `f1_token_carry_*`, `f1_hint_follow_hits` and `f1_response_capture` are likewise zero or
  constant because the collection layer records no response headers or response bodies.
* `f6_verify_backtrack` and the evidence rule E12 can never fire on this population, for the
  same reason: the WAF log contains no successful (2xx) responses, so the denominator of the
  "revisit after success" feature is always zero. Any conclusion drawn about E12 from this
  directory alone would be an artefact; the scanner negative captures in `../negative/` do contain
  successful responses and are the population on which E12 is measurable.
