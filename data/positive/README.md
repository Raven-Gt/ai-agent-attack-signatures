# Positive captures: AI penetration-testing agent traffic

Fifteen actor captures of attack traffic produced by AI penetration-testing agents that this
research project ran against its own authorised containerised vulnerable web application.

Each capture directory contains:

| File | Description |
|---|---|
| `access.jsonl` | The raw request records exactly as the target's nginx access-audit layer wrote them. |
| `meta.json` | Framework, capture label, record count, scored-actor request count, time window, AI score, fired rule ids, and checksums of the source and published capture. |

## Captures

| Directory | Framework | Capture label | Published records | Scored-actor requests | AI score | Detected at threshold 0.35 |
|---|---|---|---:|---:|---:|---|
| `DSH-1` | DSH | lab2 | 1,942 | 1,519 | 0.8030 | yes |
| `DSH-2` | DSH | lab3 | 1,666 | 1,273 | 0.7853 | yes |
| `DSH-3` | DSH | lab4 | 1,209 | 838 | 0.7475 | yes |
| `PentAGI-1` | PentAGI | lab5 | 7,615 | 1,512 | 0.7342 | yes |
| `PentAGI-2` | PentAGI | lab6 | 6,447 | 384 | 0.7740 | yes |
| `PentesterFlow-1` | PentesterFlow | lab7 | 143,441 | 767 | 0.5059 | yes |
| `CyberStrikeAI-1` | CyberStrikeAI | csai | 156 | 85 | 0.6576 | yes |
| `AutoPT-1` | AutoPT | autopt | 4,539 | 4,530 | 0.4146 | yes |
| `hackingBuddyGPT-1` | hackingBuddyGPT | hbgpt | 98 | 62 | 0.2800 | no |
| `AntiFox-1` | AntiFox | antifox | 2,799 | 2,713 | 0.6174 | yes |
| `ARTEX-1` | ARTEX | artex | 2,089 | 2,006 | 0.6174 | yes |
| `strix-1` | strix | strix | 31,213 | 31,024 | 0.7980 | yes |
| `xalgorix-1` | xalgorix | xalgorix | 168 | 47 | 0.5404 | yes |
| `raptor-1` | raptor | raptor | 1,260 | 1,252 | 0.4279 | yes |
| `pentest-ai-1` | pentest-ai | ptai | 6,905 | 6,888 | 0.2500 | no |

Fifteen actor captures in total, spanning 12 frameworks and 211,547 published request records.
Thirteen of the fifteen captures reach the decision threshold of 0.35.

## Why "published records" and "scored-actor requests" differ

A capture file contains every request the target observed during the run, including container
health checks, operator probing and traffic from other containers on the same host. The detector
operates on the *actor*: the subset of requests attributed to the agent by ground-truth source
address labelling after health-check noise removal. The scored-actor request count is the number
of requests the published score was computed over, and is the number that reproduces the score
exactly. Both numbers are given in every `meta.json`.

## Score provenance

The `ai_score`, `fired_rules` and `fired_rule_weights_by_family` fields are read from the
evaluation artifact that is the declared source of truth for scores. The scoring pipeline was
re-run independently over the released capture files and reproduced all 15 actors' request
counts, scores and fired-rule sets exactly (15/15, 0 mismatches).

## Record format

Each line of `access.jsonl` is one JSON object with the fields the access-audit layer writes:
`ts`, `rid`, `src`, `xff`, `method`, `uri`, `ruri`, `args`, `status`, `bytes`,
`rt`, `urt`, `uaddr`, `host`, `ua`, `ref`, `user`, `role`, `body`.

## Documented transformation

The captures are byte-identical to the collected originals with one exception: every byte outside
the ASCII range is percent-encoded, so that the release stays ASCII-only. This affects **64 of the
211,547 published records** (865 bytes in total): 4 records in `DSH-1`, 53 in `PentesterFlow-1`
and 7 in `strix-1`. The affected bytes are multi-byte characters inside request bodies and
request paths, including some byte sequences that are not valid UTF-8; percent-encoding them
byte by byte keeps the transform lossless and reversible, so percent-decoding the affected fields
restores the original bytes exactly.

The number of modified records and bytes is stated per capture in `meta.json`, and
`meta.json` also records the SHA-256 of both the original and the published capture file so the
transformation is auditable. Line endings, field order and the original number formatting are
preserved.

## Addresses in the captures

The `src` and `host` fields hold addresses of the evaluation environment's own container
network and of the containerised target (loopback and RFC 1918 ranges, plus the RFC 2544
benchmark range used for the reachable target address). No address of an Internet origin appears
in this directory. The request bodies contain attack payloads aimed at the evaluation target, and
occasionally contain ordinary English words that happen to be part of a payload; those are data,
not register.

## Negative results worth recording

Two captures do not reach the threshold and are released unchanged:

* `hackingBuddyGPT-1` scores 0.2800. A lightweight agent that issues single requests directly
  leaves too little evidence in the behavioural layer.
* `pentest-ai-1` scores 0.2500 and is explicitly flagged by the reverse-evidence rule E15: in
  its observed configuration the agent degenerated into dictionary-driven enumeration, which is
  behaviourally indistinguishable from a human running a word list.

Both are reported rather than dropped, because the framework-level generalisation claim in this
study is a lower bound that shrinks when a framework is added, and that is the intended behaviour
of the estimate.
