# Dataset card: behavioural traffic dataset for AI-agent-driven attack activity

| | |
|---|---|
| **Name** | AI-Agent Attack Traffic Dataset (behavioural release) |
| **Version** | 1.0.0 |
| **Release date** | 2026-11-26 |
| **Capture window** | 2026-11-23 to 2026-11-26 (positive and scanner captures); 2025-07-26 to 2025-08-25 (WAF-derived negative population) |
| **Licence** | MIT for everything under `data/`; see section 3 for what is deliberately *not* redistributed |
| **Language of this card** | English |
| **One-line description** | Raw request captures of AI penetration-testing agents and of real scanning tools against an authorised target, plus pseudonymised feature vectors for 1,582 real internet attackers, published so that traffic-level AI-attribution claims can be re-checked independently. |

---

## 1. Overview

The study this dataset supports asks a narrow question: **can HTTP request behaviour alone tell an
AI-driven penetration-testing agent apart from a human driving the same tools?**

The answer this release documents is *partly yes, with a sharp boundary*. On 15 actor captures
covering 12 agent frameworks, the detector reaches the decision threshold of 0.35 on 13 captures
and on 10 of 12 frameworks. On 1,582 real attacker actors derived from a 30-day WAF audit log, the
false-positive rate at the same threshold is 2.72% (95% CI 2.02% to 3.64%). But on 6 real
scanner actors running against the same target, 4 of 6 reach the same threshold. The false
positives are concentrated exactly where the agent delegates all of its work to conventional
scanners, which is the dominant agent behaviour observed in this study. Section 8 states the
consequences; section 11 states the numbers.

The release is deliberately split into three tiers so that a reader can stop at the tier that
matches their needs:

* **Raw evidence** (`positive/`, `negative/`): the request records as collected, plus a small
  metadata file per capture.
* **Derived vectors** (`features/`): one feature vector per real attacker actor, pseudonymised,
  with no request content.
* **Summary tables** (`aggregate/`): the detection results, the threshold trade-off, the leave-one
  framework-out results, the feature-family ablation bounds, the framework coverage matrix, the
  rule validation counts, the negative-set summary, and the checksum manifest.

---

## 2. What is in this release

| Tier | Files | Records / rows | Notes |
|---|---:|---:|---|
| `positive/` | 15 capture directories, 31 files | 211,547 request records | 12 agent frameworks; 13 of 15 captures reach threshold 0.35 |
| `negative/` | 6 capture directories, 13 files | 999 request records | Real scanner traffic; 4 of 6 reach threshold 0.35 |
| `features/` | 3 files | 1,582 actor vectors x 103 features | Pseudonymised; 1,378 browser-class and 204 tool-class actors |
| `aggregate/` | 15 files | 179 table rows in total | Summary tables and the checksum manifest |
| This card | 1 file | - | Provenance, licence, limitations, inventory |

Total published payload: 66 files, 89,038,250 bytes, plus this card and the checksum manifest.

---

## 3. Licence

### 3.1 Components licensed under MIT

Everything under `data/` is MIT licensed, matching the repository `LICENSE` file:

* `data/positive/` - the 15 AI-agent actor captures and their metadata.
* `data/negative/` - the 6 scanner actor captures and their metadata.
* `data/features/` - the pseudonymised actor feature vectors and the feature dictionary.
* `data/aggregate/` - the summary tables and the checksum manifest.
* `data/DATASET_CARD.md` and `data/README.md`.

### 3.2 Components deliberately excluded from this release

| Excluded | Reason |
|---|---|
| The 30-day WAF audit log and the raw transaction file derived from it | The WAF log used for the negative sample comes from an anonymised third-party dataset. Its raw records are therefore **not redistributed**. Only derived aggregates and pseudonymised feature vectors are shipped, in `features/` and `aggregate/`. |
| The honeypot field-data population (the `N1 honeypot` source) | Same third-party redistribution constraint. Its counts appear in `aggregate/negative_set_summary.csv`; its records are not shipped. |
| Source code of the AI penetration-testing frameworks | Not part of this release. Each framework remains under its own licence; the repository `NOTICE` file records per-framework provenance for the derived signature material published under `signatures/`. |
| Absolute local paths of the collection environment | Present in internal working artifacts; removed from every published file. |

### 3.3 Attribution and third-party names

Framework names and product names that appear in this release (in capture metadata and inside
captured user-agent strings) identify the projects that produced the observed traffic. They are
used for research attribution only; no endorsement is implied. A small number of captured
user-agent literals originate in copyleft-licensed upstream frameworks; the corresponding
signature material published under `signatures/agpl/` is covered by the repository `NOTICE`
table.

---

## 4. Data schemas

### 4.1 `access.jsonl` (one JSON object per request)

| Field | Type | Meaning |
|---|---|---|
| `ts` | string | ISO-8601 timestamp with UTC offset. |
| `rid` | string | Request identifier assigned by the target. |
| `src` | string | Source address of the request. |
| `xff` | string | Forwarded-for header value. |
| `method` | string | HTTP method. |
| `uri` / `ruri` | string | Request path and the normalised request path. |
| `args` | string | Query string. |
| `status` | integer | Response status code. |
| `bytes` | integer | Response size. |
| `rt` | number | Response time. |
| `urt` / `uaddr` | string | Upstream response time and upstream address. |
| `host` | string | Host header. |
| `ua` | string | User-Agent header. |
| `ref` | string | Referer header. |
| `user` / `role` | string | Identity and role resolved by the target from the presented token. |
| `body` | string | Request body. |

### 4.2 `meta.json` (one per capture)

Carries the framework or scanner identity, the record count, the scored-actor request count, the
time window, the AI score, the decision threshold, the verdict, the fired rule ids and their
per-family weights, the score provenance, the SHA-256 of the source capture and of the published
capture, and the number of records affected by the ASCII normalisation.

### 4.3 `features/actor_features.jsonl` and `features/actor_features.csv`

One object (or one row) per real attacker actor. See `features/README.md` for the full field
reference and for the pseudonymisation scheme. The CSV holds 9 metadata columns followed by the
103 feature columns in canonical order; `features/feature_dictionary.json` defines each of them.

### 4.4 `aggregate/` tables

| File | Rows | Content |
|---|---:|---|
| `framework_detection_actors.csv` / `.json` | 15 | One row per positive actor capture: request count, score, verdict, fired rules and their weights. |
| `framework_detection_summary.csv` / `.json` | 12 | One row per framework, with the best and worst capture score and the framework-level verdict. |
| `threshold_fpr_tradeoff.csv` / `.json` | 8 | One row per decision threshold, with recall and the false-positive rate and its 95% interval, both as published and as recomputed on the released positive set. |
| `lofo_framework.csv` / `.json` | 10 | Leave-one-framework-out: threshold calibrated without the held-out framework, then applied to it. |
| `feature_family_ablation.csv` / `.json` | 8 | Exact upper bound on recall when one feature family is unavailable. |
| `framework_coverage_matrix.csv` / `.json` | 64 | One row per audited framework repository. |
| `rule_validation_counts.csv` / `.json` | 25 | Rule-set composition and the real-traffic validation counts. |
| `negative_set_summary.csv` / `.json` | 6 | The three negative sources and their two actor-splitting granularities. |
| `checksums.csv` | 66 | SHA-256, byte size and row count for every other published file. |

---

## 5. Collection process

### 5.1 Evaluation environment

All captures were produced against the same containerised vulnerable web application, reached over
the evaluation environment's own container network. The target's nginx access-audit layer wrote
one JSON line per request, which is the source of every `access.jsonl` file in this release. The
same layer is used for the positive captures, for the scanner captures, and for the WAF-derived
population, which is what makes the populations comparable at the record level.

Where a framework refused a private-range target address, the target was given a reachable address
from the RFC 2544 benchmark range. No framework's own safety logic was bypassed: the switch used
is the one the framework itself documents for self-hosted instances, and one framework whose
blacklist is fail-closed and has no documented opt-in was abandoned instead.

### 5.2 Positive captures (AI agents)

Fifteen agent runs were captured across 12 frameworks: a project-native agent (3 captures), a
second project-native agent (2 captures), and 10 further frameworks with one capture each. Every
run used the same model service throughout the study; the collection layer was configured to
reject any model identifier other than the one in use, so no run could silently switch models.

Each capture file holds every request the target observed during the run. The detector operates on
the *actor* inside that file: the requests attributed to the agent by ground-truth source-address
labelling, after container health-check noise removal. The scored-actor request count is given in
every `meta.json` and is the request set on which the published score was computed.

### 5.3 Scanner hard-negative captures

Ten real scanning tools (ffuf, sqlmap, nuclei, nikto and others) were placed in independent
containers, each with its own source address on the evaluation environment's container network,
and were run against the same target. This produced both successful and failed responses, which
is the property the WAF-derived population lacks. The released set is the six actors whose actor
class is browser or tool; the selection rule and the two excluded actors are documented in
`negative/README.md`.

### 5.4 Real-attacker negative population

The negative population for the false-positive measurement comes from a 30-day WAF audit log
holding 151,011 attack transactions. Transactions are grouped into actors by source address;
actors with fewer than 5 requests are discarded, which leaves 2,794 actors, of which 1,582 are
classified as attacker actors (browser or tool user-agent class) and form the population the
false-positive rate is measured on. Crawler-class and no-user-agent actors are reported
separately in `aggregate/negative_set_summary.csv`, because their false-positive rate is
markedly higher and averaging them in would misstate the operating point.

Only derived data from this population is published: the raw log and the raw transaction file are
not redistributed.

### 5.5 Feature extraction and scoring

Each actor's feature vector is computed by the project's feature extractor, which produces 103
numeric features grouped into ten families: semantic causality, feedback adaptivity, rhythm,
exploration structure, repetition and verification, identity lineage, egress intelligence, tool
fingerprint, machine-generated account naming, and payload semantics. The detector then evaluates
14 evidence rules against the vector and combines the weights of the rules that fire with a noisy-OR
combination, capped at 0.25 when a reverse-evidence rule fires. The names, the families, the rule
thresholds and the weights are all fixed by the detector source that accompanies this repository;
this release publishes the vectors and the outcomes, not the thresholds.

### 5.6 Verification performed for this release

Every number in this card was re-derived from the released data or read from the evaluation
artifacts; nothing was estimated. Specifically:

| Check | Result |
|---|---|
| Positive actor scores re-computed from the published capture files | 15 of 15 reproduced exactly (request count, score, fired rule set): 0 mismatches |
| Negative actor scores re-computed from the source transaction file | 2,794 of 2,794 reproduced exactly: 0 mismatches |
| Scanner actor scores | 6 of 6 reproduced exactly: 0 mismatches |
| False positives at threshold 0.35 | 43 of 1,582, matching the published trade-off table |
| Published capture files against their collected originals | Byte-identical except for the documented ASCII normalisation |
| Address leakage check | No source address from the negative corpus appears in any published file outside `positive/` and `negative/` |
| Encoding check | Every published file is pure ASCII |

### 5.7 Source artifact map

The evaluation artifacts this release was built from are identified below by content rather than by
path, because the working environment uses non-ASCII directory names that this release does not
reproduce.

| Alias used here | Content |
|---|---|
| Evaluation JSON, methodology v3 | The 15 positive actor records (request count, score, fired rules, per-family weights), the framework-level bound table, the family ablation and the decision-line algebra. |
| Evaluation JSON, negative evaluation v2 | Per-actor scores and fired rules for all three negative sources, under both actor-splitting granularities. |
| Evaluation JSON, threshold and false-positive trade-off | The threshold sweep and the per-rule discrimination shares. |
| Evaluation JSON, leave-one-framework-out | The 10 holdout folds. |
| IOC rule set, release edition | 610 indicator rules with tier, indicator class, kind and framework attribution. |
| Framework coverage table | 64 audited framework repositories with their indicator counts and execution status. |
| Real-traffic validation report | The 30-day WAF audit log validation, 142,705 transactions. |
| Public background-traffic scan report | 9,905,794 rows of public background traffic. |
| Feature extractor and scoring source | The feature family definitions, the 14 evidence rules and their weights. |

---

## 6. Intended use

* Reproducing the detection results reported in the study, from the released data alone.
* Building and calibrating behavioural detectors over HTTP request streams.
* Testing a detection rule or model against a labelled positive set and a real-world negative set
  with a published false-positive rate.
* Teaching and reviewing the measurement methodology: what an actor-level false-positive rate
  means, why it must be counted per actor rather than per request, and how a sample-size bound
  changes when a framework is added.
* Extending the study by adding further agent captures or further scanner populations to this
  release's format.

## 7. Out-of-scope use

* **Training an AI-agent attack capability, or tuning one.** The captures are a detection
  benchmark, not an attack manual.
* **Building a list of paths, payloads or identities to probe a target.** The released captures
  contain real attack payloads and endpoint paths observed against the study's own target; using
  them against any system that has not authorised testing is out of scope.
* **Attributing a specific actor, or de-anonymising one.** The pseudonymisation of the negative
  population is a privacy measure with a known residual weakness (section 9.3); attempting to undo
  it against a third party is out of scope.
* **Any claim that the detector generalises to agent frameworks outside the 12 covered here.** The
  framework-level bound in section 11 is the strength of the claim this evidence supports, and it
  is a lower bound on an unseen framework.
* **Deployment decisions taken on the threshold alone.** Section 8.3 explains why the threshold
  depends on which negative population the deployment faces.

---

## 8. Known limitations and biases

### 8.1 The behavioural layer cannot separate an agent from the tools it drives

This is the central limitation and it is measured, not hypothesised. Four of the six released
scanner actors reach the decision threshold. Raising the threshold does not fix it: within the
scanner population the rate stays at 4 of 6 from threshold 0.35 up to 0.55, and only collapses
once the threshold reaches 0.60, at which point the framework-level recall on the released set
falls to 6 of 12. The supported recommendation is to combine passive HTTP behaviour detection
with correlation of attack-source outbound traffic.

### 8.2 The negative population has a structural blind spot

The WAF audit log records only requests the WAF matched, so it contains no successful responses.
Any feature that depends on a 2xx response is structurally zero there, which is why the "revisit
after success" feature and its rule E12 never fire on the 1,582 published vectors. That is an
artefact of the instrumentation. The scanner captures in `negative/` do contain successful
responses, and E12 fires on every released scanner actor, which shows E12 separates nothing.
Readers must not draw conclusions about E12 from `features/` alone.

### 8.3 The threshold is population dependent

At threshold 0.35 the false-positive rate is 2.72% on the WAF-derived real-attacker population and
4 of 6 on the scanner population. A deployment that faces scanner-shaped traffic needs a different
operating point from one that faces human-driven attack traffic, and the trade-off table in
`aggregate/threshold_fpr_tradeoff.csv` only describes the first population.

### 8.4 The false-positive rate is a point estimate on a finite population

At 43 false positives out of 1,582 actors the 95% interval is 2.02% to 3.64%. The rate is
counted per independent actor, not per request, which is the correct unit for deployment but
means the estimate does not improve by adding more requests to the same actor.

### 8.5 The scanner negatives are dominated by one tool

Of the 999 released scanner records, 910 carry the ffuf user agent; nikto and masscan contribute 6
records each and the remaining tools are a handful. The evidence supports a statement about
ffuf-style content discovery, not a statement about scanning tools in general.

### 8.6 The released negative records are nested inside one released positive file

All 12,666 records of the scanner source file are already present inside
`positive/PentesterFlow-1/access.jsonl`, because both were recorded by the same access-audit
layer against the same target inside the same window. The scored positive actor of that capture is
a different actor on a different source address, so the detector's measurements are unaffected,
but a reader who trains on `positive/` and evaluates on `negative/` must remove the nested
records first.

### 8.7 The published captures are not a representative sample of production traffic

They come from one deliberately vulnerable target, one collection layer, one model service and one
operator. Their endpoint structure, response-code distribution and authentication behaviour are
properties of that setup. The WAF-derived population is the opposite trade-off: real and
adversarial, but with no successful responses and no session continuity.

### 8.8 Sample sizes bound the generalisation claim

Fifteen actor captures over 12 frameworks support a framework-level single-sided 95% lower bound
of 0.779 (0.05 raised to the power of 1 divided by 12). Reaching a 95% lower bound would require
about 72 captures, and a 99% lower bound about 368, at the cost of a false-positive bound below
1% that needs 368 independent negative actors. Adding more captures of frameworks already
covered does not improve the bound; only adding frameworks does.

### 8.9 Feature families with structurally zero values

Eight egress-intelligence features and the response-dependent features are zero or constant in
`features/` because the collection layer records no outbound traffic and no response body. They
are published as computed, and the corresponding rules are excluded from any claim that depends
on them.

### 8.10 The published trade-off table is one step behind the released positive set

The published threshold sweep was produced against an earlier positive set of 13 actor captures
over 10 frameworks. The released positive set holds 15 captures over 12 frameworks. The
`threshold_fpr_tradeoff.csv` table therefore carries both the artifact's recall column and a
recomputed recall column for the released set, and the recomputed column is the one that
corresponds to `positive/`.

---

## 9. Ethics, compliance and privacy

### 9.1 Authorisation and scope

Every request capture in `positive/` and `negative/` was generated by this research project
against its own authorised containerised target, in an isolated evaluation environment. No third
party system was scanned, and no capture contains traffic to or from a system that the project
does not own. The scanners in `negative/` were run against that same authorised target.

### 9.2 Third-party data

The WAF audit log from which the negative population was derived comes from an anonymised
third-party dataset. Its raw records are **not** redistributed in this release, and the only
things shipped from it are the pseudonymised per-actor feature vectors in `features/` and the
aggregate counts in `aggregate/`. The same restriction applies to the honeypot field-data
population.

### 9.3 Pseudonymisation and its residual weakness

Real attacker actors are published only under a pseudonymous identifier: the prefix `actor_`
followed by the first 12 hexadecimal characters of the SHA-256 digest of the source address. No
source address, request content, path, query string, body or response code of any individual
request appears in `features/`.

The construction is unkeyed, as specified for this release, which has a known consequence worth
stating plainly: an adversary who already holds the source log could confirm a candidate address
by recomputing its digest, and the IPv4 address space is small enough to enumerate. A release that
must resist re-identification should use a keyed digest under an unpublished salt. This release
keeps the unkeyed construction so that identifiers are reproducible across recomputations.

### 9.4 Personal data

The capture layer records the identity and role that the target resolved from a presented token.
Those values are account names created by the study's own agents against the study's own target;
they are not natural persons' credentials. The released captures do contain, verbatim, the
usernames that the agents generated, which is part of the machine-identity evidence that the
study reports.

### 9.5 Payload content

The released captures contain real attack payloads, including SQL injection, command injection,
path traversal and server-side request forgery strings. They are published because they are the
evidence for the payload-semantics axis and for the indicator rules, and because they were aimed
at the study's own target. They are not published as a payload collection for use against other
systems.

### 9.6 Incidental English words inside payloads

Captured payload strings occasionally contain ordinary English words. Those are data, not
register: they were written by the scanning tools, not by the authors of this release.

---

## 10. File inventory, row counts and checksums

`aggregate/checksums.csv` is the machine-readable manifest of every published file except
itself and this card, and carries the same numbers as the table below.

`rows` counts data rows for CSV files (header excluded), records for JSONL files, and top-level
elements for JSON files; it is empty for Markdown files.

| File | Rows | Bytes | SHA-256 |
|---|---:|---:|---|
| `README.md` | | 2,415 | 8c8bfffd2d171bbafabbe4978150a938d75efef43230bd49946c245a8fb5be51 |
| `aggregate/checksums.csv` | 66 | 6,944 | a96ced355383b5a41593d41e24b226eda4b35b707fdb3f48d24e88c4b4f64ddc |
| `aggregate/feature_family_ablation.csv` | 8 | 227 | 527b2865344a9703c09dc55c3f05ff7b18b3fabd340adf35d043edbd92f3e1ae |
| `aggregate/feature_family_ablation.json` | 1 | 344 | c840c1a8d02a82ff5e3279a5881130cb740e89afd7bdba74a48e5a73ad229ace |
| `aggregate/framework_coverage_matrix.csv` | 64 | 9,543 | f270c7e51305540686dcad80bc84d31f3dc848c9174d7bf0de69efeaa280dac6 |
| `aggregate/framework_coverage_matrix.json` | 1 | 26,529 | 8b664d1ddc4733fceae43e7ab6e55b88a2219262bf584ee635e4e31d96958cc7 |
| `aggregate/framework_detection.json` | 1 | 4,540 | 8942f472064c081a06b576cc4fdb5e1b782282e13839f12694ab12303c02302c |
| `aggregate/framework_detection_actors.csv` | 15 | 1,747 | fe928013888c4b1530aba31afd5528a27bfc4e072491f6cd3ff791c5f5fe060c |
| `aggregate/framework_detection_summary.csv` | 12 | 1,234 | 52d16d82f413c159e2e0a26650f4d540c543b0bd349903370da99e845f4aa2ba |
| `aggregate/lofo_framework.csv` | 10 | 770 | b5f54eac8594b7abb903438381535363c5d30a26356447ecfddaba0fa1cf658d |
| `aggregate/lofo_framework.json` | 1 | 2,302 | 0fc6ce8bde5a1f2987e76e3232739b15d6b86f07a3690870f3bef39b2ddb3490 |
| `aggregate/negative_set_summary.csv` | 6 | 656 | a00f3ebabb9663aee9ef192c22a640bc3be08e6c04c02ce1330164fb9ad6e15a |
| `aggregate/negative_set_summary.json` | 1 | 1,073 | 34453ec7fff83c1dc4ed69a7eb4dae33208a77a019227b2599c1bf57794a8d73 |
| `aggregate/rule_validation_counts.csv` | 25 | 1,610 | 080cdbdd0d5e42af7e7d749aa3a440868b7368937d7a3ffd2eef2fde3e541135 |
| `aggregate/rule_validation_counts.json` | 1 | 5,657 | bc021151712b3dba48a3cbd39f76581b388d69f3619e8e4ae40404b3a4b084fd |
| `aggregate/threshold_fpr_tradeoff.csv` | 8 | 1,498 | af3455251a6a8ad05ef7ecb7e4aca5b9c4842c0ac3c824942e6d32a8fdbf69e9 |
| `aggregate/threshold_fpr_tradeoff.json` | 1 | 5,613 | 260e609b73877bca37297b50d3f5d684c6c77248f005c5356756274c98d442f0 |
| `features/README.md` | | 5,324 | 330a3fea37f880ff6ecbdc6a62619fca05a92e1c3105b711057e16111eed67b4 |
| `features/actor_features.csv` | 1,582 | 1,145,601 | b9dfd4cf850dd66b2be255ab17150c034d2d715a2bdb42e6e80133ad0be2d9a3 |
| `features/actor_features.jsonl` | 1,582 | 4,891,807 | 59c964f5d481a2abaad319d06e0399fdca881c1b39910bde4fb9852fa499ae5e |
| `features/feature_dictionary.json` | 1 | 18,875 | 9258473751b69e0ca138ec7f5681960cecdd5da97e7f8e397d1f5dba6181a22d |
| `negative/README.md` | | 5,960 | 6d4d86bbc82044fb9927b675d93fcb2b08438ca068845e9fb3e917656d8a8b12 |
| `negative/_index.json` | 1 | 3,737 | 0e25e011e962a3ddaa8c2c78330e8dc723a75a2fd7ba7cc0347296d366f6e3cf |
| `negative/scanner-01/access.jsonl` | 32 | 10,148 | 236d6befe5dda6edce93e9b1a667dfc488f9798ad5d25a20f63f2466b4180b73 |
| `negative/scanner-01/meta.json` | 1 | 1,004 | 04145e0294b283a998a8364a1bcadec3330f09d3df08b31362d8a924e8e12324 |
| `negative/scanner-02/access.jsonl` | 205 | 73,496 | ca083d86c352874b3fe9bcf4730569dd71816e0c520e546fb40f01cbfffea7d6 |
| `negative/scanner-02/meta.json` | 1 | 1,120 | 37b50e50a595f1825258bbe50fdb45f14ac4666e5dabf7161e7413207d0f81dc |
| `negative/scanner-03/access.jsonl` | 144 | 51,609 | 1beef7bb03127b14c03cededdcc22cd48b1778b6cc3953c2454a716a0738b649 |
| `negative/scanner-03/meta.json` | 1 | 1,109 | 11c2e079485c692d430fe76c1ed5edba879d8eb9effccffaaed1bf0a3c108081 |
| `negative/scanner-04/access.jsonl` | 405 | 149,917 | a68091bdb9964498d15ff884da62da75bd987b0ccd7d660705ae14a1460b98e1 |
| `negative/scanner-04/meta.json` | 1 | 1,121 | 776eeb341c3894371c8f774226f283f47499649f5ae1a9d2cda6b1c57ab2bdb3 |
| `negative/scanner-05/access.jsonl` | 144 | 51,665 | 17f0cd74f4af6ba7c3c9986e1204700045bcffd540e08939bac207e12b91f0ca |
| `negative/scanner-05/meta.json` | 1 | 1,098 | 76eddc31f86103c848a61e4c22896626f2aec583b1c9e08b429ae87e73905e09 |
| `negative/scanner-06/access.jsonl` | 69 | 24,956 | cf356d6b1c229daa5f7dc0166bad79c647111558f4bcb45316f13c732d5694ab |
| `negative/scanner-06/meta.json` | 1 | 1,073 | 7467c7f231df914499df89cc0880e885873c6665164cc025ab548ca3836513d4 |
| `positive/README.md` | | 5,285 | efa18e5a0fdc747951b56bd9a48fbb8ad086f16226a468de89c8003369777811 |
| `positive/_index.json` | 1 | 7,788 | 5828392decc314c3d7ed071a869878b0d1c9ec2fe825f01df97ecc9b0ee97209 |
| `positive/AntiFox-1/access.jsonl` | 2,799 | 1,141,435 | bacf29128d991ad181d7006bc9acd8f41aae2d51ab362d1fc807b02f2c9cfb54 |
| `positive/AntiFox-1/meta.json` | 1 | 1,429 | d1200d9beefb0f66e1a4a37870b604410a502645849541872dd916408f30f438 |
| `positive/ARTEX-1/access.jsonl` | 2,089 | 849,685 | 21906fbc2cc2e5b0636f8d8bb6439fdf7552eae591bc6625b2c491d3541b2643 |
| `positive/ARTEX-1/meta.json` | 1 | 1,422 | 5f1f1a5b18bddb4b9b481f7c0e49e2bdba76dbcb8eb14360916da054b6a6d537 |
| `positive/AutoPT-1/access.jsonl` | 4,539 | 2,821,621 | 7ee04c030d2db812d865161e9731525cd24a42f4f56ca6e3c59de729346f4c21 |
| `positive/AutoPT-1/meta.json` | 1 | 1,380 | ab1a7743e8246d99c44aa061812db841a8f060e4105c1fbfa815528a08b39917 |
| `positive/CyberStrikeAI-1/access.jsonl` | 156 | 50,269 | 2f6f12522bcae44c2607400c24f1e81185013f2b2b2ca25711867912f51a3be5 |
| `positive/CyberStrikeAI-1/meta.json` | 1 | 1,436 | c929a1273c8f5166f321f6121e0d8d7b0fa56fa690fbd9cb241098975695afb1 |
| `positive/DSH-1/access.jsonl` | 1,942 | 944,550 | 1b25585e6bb89d38f7910b6da7384bf3236747ae68a96859287c775d8317133d |
| `positive/DSH-1/meta.json` | 1 | 1,464 | d369a72a1f57430206a0636fb8a8136500970162d3319aead2d78d6bb99c48dd |
| `positive/DSH-2/access.jsonl` | 1,666 | 714,630 | 16e4d2e020cf8ba6c14fc1a17f925d27ff6a4f4d14298db4850e7dcfd4ac6bf7 |
| `positive/DSH-2/meta.json` | 1 | 1,460 | 5ab61c17758c30f9ef18eaf921319773341717d10c6f733627acf099cc3fbdee |
| `positive/DSH-3/access.jsonl` | 1,209 | 528,220 | 17bd78a95e6d2675ab4b46d628782608e6576c80b0982715bb0843c8b9285016 |
| `positive/DSH-3/meta.json` | 1 | 1,436 | 78768eb0e65170e1a7bc83fd238df07c8ed4c625849794c624f129a0ccfebf01 |
| `positive/hackingBuddyGPT-1/access.jsonl` | 98 | 41,638 | 514a0901251aa5ddc7d1c0474b6b40f4748a2c4123c6dd167589d8c73dfee159 |
| `positive/hackingBuddyGPT-1/meta.json` | 1 | 1,364 | f3545accb714d0b4323e54c7a98240a3b9a4e8277c73f912901bb06d8bfbedb4 |
| `positive/PentAGI-1/access.jsonl` | 7,615 | 2,320,212 | e3f1adaeb33b91cece1ad1578f0d9edc50f41df219283d6ac2a456ab9cc5a247 |
| `positive/PentAGI-1/meta.json` | 1 | 1,431 | b167837e938c59ac156adc21f7b809c2fb8a6e4a431cee7af09f1cea24f72bad |
| `positive/PentAGI-2/access.jsonl` | 6,447 | 1,908,734 | cba5bdc46ab688eab7b310594f59508789a43548425c6e4ea2285dc8f66c6692 |
| `positive/PentAGI-2/meta.json` | 1 | 1,453 | ef9b0f40f5bac1398d69e9ccd56506e37cd7f9fb95a4ad08be873493d3aeb248 |
| `positive/PentesterFlow-1/access.jsonl` | 143,441 | 55,654,307 | cfd36f738839adfb06b71a9288abc51441080f502795bbe9e813cdea2c05637f |
| `positive/PentesterFlow-1/meta.json` | 1 | 1,412 | 78be3621e3756dcf3bb555b770fc0ed831ce9f2dea3ab18be7d1b64919cce740 |
| `positive/pentest-ai-1/access.jsonl` | 6,905 | 2,802,128 | 2385dcb8ffe9f5792fac483a521db9efebf7f2a2a1171b11523f1e253548449b |
| `positive/pentest-ai-1/meta.json` | 1 | 1,418 | ddb74aad9a0124d6825161383d82305c811f23605914a275c55dc1ddf5209833 |
| `positive/raptor-1/access.jsonl` | 1,260 | 573,255 | fb8953579154feb8e6ac89f898e9b38cc9033d9d97c8e3c551383918370af1c8 |
| `positive/raptor-1/meta.json` | 1 | 1,372 | e1dcb54b676d1dbf7a7073663a78b1e1c389eecf1a12ddc5f5af39ac5dc253e3 |
| `positive/strix-1/access.jsonl` | 31,213 | 12,090,704 | b8937a60a4a28cfff55fea8b0488ab39c9c78accb7a0ed7ee438e6bdc8739dcd |
| `positive/strix-1/meta.json` | 1 | 1,456 | ce82e336977eb81f97ec958a917accb3a30bf7c94bab9c89794134126fd84274 |
| `positive/xalgorix-1/access.jsonl` | 168 | 57,099 | e339f81b10d701082c9f9d9a657a9d574d7d8001a32a45f60eb655c76839f0d2 |
| `positive/xalgorix-1/meta.json` | 1 | 1,379 | 45cc55260403ab7a59fcc88041c719030d4f9adeefaa1be6dafc1506e98fb752 |

This card itself is not in the manifest, because it carries the manifest. Its SHA-256 is reported
in the release notes that accompany this release.

---

## 11. What the released data supports

All numbers in this section are read from the files in this release.

### 11.1 Detection on the positive set

* 13 of 15 actor captures reach the decision threshold of 0.35; the capture-level recall on the
  released set is 0.867.
* 10 of 12 frameworks are detected, giving a framework-level single-sided 95% lower bound of
  0.779 for the claim "an agent framework not seen before is detected".
* The two undetected captures are `hackingBuddyGPT-1` (0.280, a lightweight agent that issues
  single requests directly) and `pentest-ai-1` (0.250, explicitly flagged by the reverse-evidence
  rule E15 as a dictionary-driven enumerator).
* Leave-one-framework-out: 9 of 10 holdout folds detect the held-out framework; the failing fold is
  `hackingBuddyGPT`.

### 11.2 False positives on the real-attacker population

* 43 of 1,582 attacker actors reach the threshold: a false-positive rate of 2.72%, 95% interval
  2.02% to 3.64%.
* The false-positive rate rises to 24.21% at threshold 0.25 and falls to 0.19% at threshold 0.50.

### 11.3 False positives on the scanner population

* 4 of 6 scanner actors reach the threshold at 0.35, 0.40 and 0.45; 2 of 6 at 0.50 and 0.55.
* The framework-level recall that would be needed to reach 0 false positives on this population
  costs 4 of the 12 released frameworks.

### 11.4 Feature-family sensitivity

The exact recall upper bound when a family is unavailable is 0.933 for F10, F4, F5, F7 and F9,
0.867 for F6 and 0.733 for F3, against a base of 0.933. F3, the feedback-adaptivity family, is the
only family whose absence is materially costly.

### 11.5 Rule validation

* The indicator rule set holds 610 rules: 272 in tier T1, 126 in tier T2 and 212 withdrawn, over
  44 distinct framework labels.
* On 142,705 real attack transactions from the 30-day WAF audit log, 0 T1 rules match after the
  tier corrections; the body field was not present in that log, so the body rules were validated on
  the scanner population instead.
* On 9,905,794 rows of public background traffic, 0 T1 rules match.

---

## 12. What was not measured

Stated explicitly so that no reader infers more than the evidence supports.

* **Precision on the positive set** is not a meaningful quantity: every released positive capture
  is an AI-agent run by construction, so the positive class has no negative members.
* **Human-driven attack traffic** is absent from the release. The study notes that real human
  manual probing could not be obtained, so the false-positive rate characterises automated
  attackers and not human ones.
* **Detector behaviour against agent frameworks outside the 12 released ones** is not measured.
  The leave-one-framework-out folds and the 0.05^(1/k) bound are the strongest available
  statements, and both are lower bounds.
* **Detector behaviour against scanning tools other than ffuf-style discovery** is not measured;
  the released scanner population is dominated by one tool family (section 8.5).
* **The effect of the collection layer's missing response bodies and missing outbound-traffic log**
  on the achievable recall is not measured; the structural-zero features are published as computed
  and the affected rules are excluded from the claims in section 11.
* **Any long-term drift behaviour** of agent frameworks is not measured: the positive captures span
  four days of collection.
