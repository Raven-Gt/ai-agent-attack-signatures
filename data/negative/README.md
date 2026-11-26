# Negative captures: scanner traffic against the evaluation target

Six actor captures of traffic produced by real scanning tools running against the same
containerised target that produced the positive captures in `../positive/`. These are the
*hard negatives* of the study: they are attack traffic, they contain successful responses, and
they look nothing like an ordinary visitor.

## Files

Each capture directory contains:

| File | Description |
|---|---|
| `access.jsonl` | The raw request records for that actor, in collection order. |
| `meta.json` | Source address, tool-signature histogram, status-class histogram, record count, time window, AI score, fired rule ids, and the checksum of the published capture. |

## Captures

| Directory | Source address | Actor class | Records | 2xx / 3xx / 4xx | Dominant tool signature | AI score | Flagged at threshold 0.35 |
|---|---|---|---:|---|---|---:|---|
| `scanner-01` | 127.0.0.1 | tool | 32 | 32 / 0 / 0 | curl | 0.1000 | no |
| `scanner-02` | 172.34.0.10 | tool | 205 | 13 / 9 / 183 | ffuf | 0.5972 | yes |
| `scanner-03` | 172.34.0.11 | tool | 144 | 16 / 6 / 122 | ffuf | 0.5972 | yes |
| `scanner-04` | 172.34.0.12 | tool | 405 | 17 / 6 / 382 | ffuf, plus nikto and masscan | 0.2500 | no |
| `scanner-05` | 172.34.0.13 | tool | 144 | 16 / 6 / 122 | ffuf | 0.5972 | yes |
| `scanner-06` | 172.34.0.15 | browser | 69 | 5 / 3 / 61 | ffuf | 0.5423 | yes |

999 published request records in total, of which 99 are successful (2xx) responses.
Four of the six captures reach the decision threshold of 0.35 - a scanner-side false-positive
rate of 4/6 on this population. That is the study's sharpest boundary result and the reason the
final recommendation combines passive HTTP behaviour detection with attack-source egress
correlation rather than relying on the behaviour layer alone.

## Selection rule

The source file contains **8** IP-level actors and 12,666 request records. The released set is the
**6** actors whose actor class is `browser` or `tool`, which is the operational definition of an
attacker actor used throughout the evaluation and which is what the evaluation artifact records
as its attacker-class count for this source.

Two actors of the same source file are **not** released:

* `172.34.0.1` (11,582 records in the source file) is the long-lived tool container that carries
  the bulk of the scanning workload; its user-agent blob mixes ffuf, nikto, masscan and browser
  user agents, and the presence of public search-engine user agents makes the user-agent
  heuristic classify it as `crawler`.
* `172.34.0.14` (85 records) is classified `crawler` for the same reason (it carries a public
  search-engine user agent alongside its scanner traffic).

Both are listed with their scores in `_index.json` under
`excluded_crawler_class_actors`.

## Relationship to the positive captures

The scanner source file was recorded by the same access-audit layer, against the same target,
inside the capture window of the `PentesterFlow-1` positive capture. All 12,666 of its records
are therefore already present inside the published `../positive/PentesterFlow-1/access.jsonl`
file. The released negative records are nested inside that one released positive file; they are
not a disjoint set of published bytes.

This does not affect the detector's measurements, because the scored positive actor of
`PentesterFlow-1` is a different actor on a different source address (767 requests, source
address 172.26.169.59), disjoint from all six released negative actors. It does affect reuse:
a reader who trains on `../positive/` and evaluates on `../negative/` must remove the nested
records first, or restrict the negative set to the request identifiers that do not appear in the
positive capture.

## Which tools are actually present

Being precise about this matters, because it bounds what the released negative set can support.
Counting user-agent markers over the six released captures:

| Tool signature | Requests in the released set |
|---|---:|
| ffuf (user agent `Fuzz Faster U Fool v2.1.0-dev`) | 910 |
| curl | 35 |
| generic browser user agents | 25 |
| python-requests | 13 |
| nikto | 6 |
| masscan | 6 |
| go-http-client | 2 |
| wget | 2 |

In the full source file, ffuf also dominates; sqlmap contributes a single request and
gobuster, nuclei, dirb and nmap contribute none. The released negatives are therefore
predominantly **ffuf** traffic, not a balanced sample across tool families. Any conclusion of
the form "the detector behaves the same against every scanner" would go beyond this evidence; the
supported statement is that it behaves this way against ffuf-style content discovery.

## Record format and transformation

Each line of `access.jsonl` is one JSON object with the same fields as the positive captures
(`ts`, `rid`, `src`, `xff`, `method`, `uri`, `ruri`, `args`, `status`, `bytes`, `rt`, `urt`,
`uaddr`, `host`, `ua`, `ref`, `user`, `role`, `body`). The records are byte-identical to the
collected originals: none of the 999 released records contains a byte outside the ASCII range, so
the ASCII normalisation applied elsewhere in this release changes nothing here.

## Addresses in the captures

The `src` values are addresses of dedicated scanner containers on the evaluation environment's
private container network and of the loopback interface. They are not Internet source addresses,
and no third-party address appears in this directory.

## Why these captures are valuable

They are the only released population that combines attack intent with successful responses.
The WAF-derived population in `../features/` contains no 2xx responses at all, which makes the
"revisit after success" feature and its evidence rule E12 unmeasurable there. In these captures
E12 fires on every released actor, confirming that E12 separates nothing: a scanner that probes
a path before exploiting it produces exactly the same pattern as an agent that verifies a
finding.
