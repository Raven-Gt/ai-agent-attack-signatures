# Methodology

This document specifies the detector precisely enough to reimplement it. Every constant is the
value in the shipped code: `research/engine/evidence.py` (rules and thresholds),
`research/engine/features.py` (feature extraction), `research/engine/segment.py` (actor
segmentation) and `research/engine/ioc_match.py` (signature matching).

---

## 1. The decision unit: one behavioural actor

> **The decision unit is a behavioural actor: all requests issued by one source address within
> one time window.**

The actor, not the request, is what gets a verdict. Two segmentation modes are provided because
the study uses two populations and both are reproduced:

| Mode | Rule | Used for |
|---|---|---|
| `session` | one actor per (source address, contiguous burst); a new actor starts when the silence since that address's previous request exceeds **600 s** | the positive corpus (real AI agent runs) |
| `window` | one actor per (source address, fixed **10-minute** window) | the negative corpus (real internet attackers), so that repeated bursts by one attacker do not collapse into a single actor |

Container health checks (`/health`, `/healthz`, `/ready`, `/live`) are removed before
segmentation. A docker healthcheck stream is not attacker behaviour, and leaving it in inflates
the request rate and the burst ratio of every actor.

### 1.1 Why the actor and not the request

* **The question is about the source, not the request.** A defender's question is "is this
  source an AI agent?", not "is this request malicious?". A per-request verdict cannot answer
  it: a single agent request looks exactly like a single script request.
* **The evidence is inherently cumulative.** Every rule except the probe rule is a statement
  about a *distribution* over many requests - how many templates, how much 404 tolerance, how
  many identities, how quickly the rate changes. No single request carries that.
* **The source address must not become a feature.** The address is only a grouping key. It is
  never entered into the feature vector, so the detector cannot cheat by memorising an address
  - and it cannot be defeated by rotating addresses either, because the behaviours survive the
  rotation.
* **Alerting on requests does not scale.** On the 9,905,794-request public traffic scan, 1 of
  80,987 source addresses matched two or more signature rules. The same data alerting per
  request would produce 32 alerts on the same 32 addresses, with no additional information. The
  actor is also the unit in which the false-positive rate is measured.
* **The 600-second window matches the operational reality.** A single agent run is a burst; the
  gaps between its bursts are longer than its internal think-time but shorter than a human's
  session. Splitting there isolates the run.

The consequence, stated as a caveat rather than a virtue: the detector says nothing about
whether an *individual request* was malicious. That is the payload layer's job, and the two
layers are orthogonal by construction (see section 8).

---

## 2. Feature families

**103 feature values** are extracted per actor, in **11 families** (F1, F3, F4, F5, F6, F7, F8,
F9, F10, F11, F13). A twelfth family, F2 (active probes), is declared but is **not computable**
under the current collection layer, which records no response headers and no response bodies;
its five columns are marked unavailable rather than filled with invented zeros.

The authoritative per-feature dictionary ships as
`data/features/feature_dictionary.json` (103 entries, each with its family and a one-line
description of what it measures).

### 2.1 Path templating, done first

Before any counting, the request path is templated: UUIDs, hex strings of 16+ characters,
e-mail addresses and integers of two or more digits are replaced by `{id}`, `{email}` and
`{id}` respectively. `/orders/1` and `/orders/2` are then one endpoint, not two. Without this,
an agent enumerating identifiers would look like an agent visiting many endpoints, and the
enumeration-breadth features (F5, F6) would be meaningless.

An **endpoint family** is the first path segment (with a small explicit exception list for
multi-segment service prefixes). The family is the unit of "did the actor change route?", which
several rules depend on.

### 2.2 The families

| Family | Name | Features | What it measures |
|---|---|---:|---|
| **F1** | semantic causality | 7 | Does the next action depend on the previous response? Number of consecutive request pairs whose authenticated identity differs, identity-switch rate, count of real switches, response-capture availability flag, token-carry hits and ratio, hint-follow hits. Two of these are structurally zero without response capture. |
| **F3** | feedback adaptivity | 9 | Does the actor change route after an error? Error count, share of errors that switch to a different endpoint family, share that switch to a different template, share that stay on the same template, share of errors followed within 3 requests by a 2xx, number of distinct error families, **abandonment rate of unusable endpoint families**, and the 404 and 403 continuation rates. |
| **F4** | rhythm | 17 | Request count, inter-request gap CV / median / p90 / max, share of zero-length gaps, log-gap bimodality coefficient, largest 1 s and 10 s burst, burst share, think-time share, think-time CV / median / max, machine speed, the machine-speed x human-thinking composite, and the log-gap entropy. |
| **F5** | exploration structure | 19 | Breadth, depth and entropy of the endpoint space: distinct templates, template entropy, endpoint-family count and entropy, maximum depth, status entropy, shares of 404 / 5xx / 2xx / 401 / 403, share of 500-as-signal, **duration**, **rate (requests per minute)**, static-asset share, discovery rate, HTTP method count, body share, argument share. |
| **F6** | repetition and verification | 8 | Number of templates revisited and their share, repeated-request share, **maximum distinct ids enumerated under one template**, number of templates with multiple ids, **2xx-then-revisit rate**, maximum parameter variants on one endpoint, maximum repeats of one endpoint. |
| **F7** | identity lineage | 8 | Distinct identities, distinct roles, unauthenticated share, identity churn (identities per minute), identities per 100 requests, latency to first authentication, whether the actor never authenticated, administrative-role share. |
| **F8** | egress intelligence | 8 | Outbound attempts observed during the attack window: total, distinct destinations, and counts classified as code host, CDN, LLM API, cloud metadata; outbound rate and outbound attempts inside the window. **All eight are structurally zero when only inbound logs exist.** |
| **F9** | tool fingerprint | 8 | User-agent families and entropy, UA switches and switch rate, whether a browser or a scanner is present, non-curl share, UA block share. Reported on a separate axis; it answers "which tool", not "who decided". |
| **F10** | machine-generated naming | 6 | Number of accounts, share with a "label.timestamp" structure, share with a timestamp suffix, share with a dotted-label structure, label entropy, share with a sequence suffix. |
| **F11** | payload semantics | 11 | Payload hit total, hit kinds and density, plus per-kind counts for SQL injection, XSS, SSRF, path traversal, command injection, JWT tampering, mass assignment and NoSQL injection. This is the **maliciousness axis**, orthogonal to the AI axis. |
| **F13** | configuration-probe axis | 2 | Share of requests to configuration and management paths, share to API paths. |
| **F2** | active probes (unavailable) | 0 of 5 | Canary-token inheritance, transformation challenge, hint following, probe score. Requires response-side capture; **not computable** under the current collection layer, and E10 is excluded from the algebra for this reason. |

Family totals measured from the shipped extractor: F1 7, F3 9, F4 17, F5 19, F6 8, F7 8, F8 8,
F9 8, F10 6, F11 11, F13 2 = **103**.

---

## 3. Evidence rules E1-E15

Each rule is a boolean predicate over the feature vector, with a weight and a natural-language
reason that is emitted with the alert so that an alert can be understood and overturned. The
authoritative implementation is `research/engine/evidence.py`; the thresholds live in its
`PARAMS` dictionary so that they can be perturbed for sensitivity analysis.

| Rule | Name | Family | Weight | Exact condition (all thresholds from `PARAMS`) |
|---|---|---|---:|---|
| **E1** | structural scale - unfalsifiability | F5 | **0.34** | `f5_duration_s > 900` AND `f5_distinct_templates >= 40` AND `f5_404_ratio > 0.25` |
| **E2** | machine speed x human thinking (supporting) | F4 | **0.15** | `f4_burst_ratio > 0.25` AND `f4_think_ratio > 0.10` AND `f4_think_max > 120` |
| **E3** | identity lineage - rotation over several accounts | F7 | **0.24** | `f7_distinct_users >= 4` |
| **E4** | machine-like account naming | F10 | **0.22** | `f10_user_count >= 3` AND `f10_machine_named_ratio > 0.40` |
| **E5** | systematic route change after an error | F3 | **0.20** | `f3_err_count >= 8` AND `f3_err_new_family > 0.45` |
| **E6** | pruning of dead branches | F3 | **0.16** | `f3_err_count >= 8` AND `f3_family_prune > 0.35` |
| **E7** | enumeration breadth | F6 | **0.14** | `f6_enum_max_ids >= 3` OR `f5_distinct_templates >= 50` |
| **E8** | egress intelligence during the attack (supporting only) | F8 | **0.20** | evidence from another family already exists AND (`f8_egress_codehost > 0` OR (`f8_egress_in_window >= 5` AND `f8_egress_distinct >= 3`)) |
| **E9** | orchestration of several execution channels | F9 | **0.12** | `f9_ua_families >= 3` |
| **E10** | active probe evidence (strongest) | F2 | **0.95** | `f2_probe_score > 0` - **not computable** under the current collection layer |
| **E11** | 404 tolerance and persistence | F3 | **0.12** | `f3_404_tolerance > 0.85` AND `f5_404_ratio > 0.35` |
| **E12** | backtrack verification after a success | F6 | **0.10** | `f6_verify_backtrack > 0.02` |
| **E13** | - | - | - | **not implemented.** The identifier is reserved; the study's own notes record that a candidate rule under this id was falsified by real data and withdrawn rather than shipped. |
| **E14** | dictionary brute-force discrimination (reverse evidence) | F13 | **0.00** | `f13_config_ratio >= 0.35` AND `f5_2xx_ratio <= 0.05` |
| **E15** | dictionary-driven high-frequency enumeration discrimination (reverse evidence) | F3 | **0.00** | `f5_distinct_templates >= 200` AND `f5_404_ratio >= 0.85` AND `f5_2xx_ratio <= 0.05` AND `f5_rpm >= 60` |

### 3.1 Why the weights are what they are

| Design | Value | Reason |
|---|---:|---|
| Highest single weight among usable rules | 0.34 (E1) | Guarantees that no single rule can reach the 0.35 decision threshold |
| Rules whose weight was reduced by real data | E2: 0.30 -> **0.15** | E2 fires on 44.6% of real-world botnet sessions against 50% of the lab's own AI agents. It describes "burst plus an occasional pause", which is a property of every automated attacker, not of AI. It is retained as supporting evidence only. |
| Outbound intelligence | E8 = 0.20, and gated on other evidence | An outbound interception log cannot be reliably attributed to a behavioural actor. E8 may only *support* evidence produced by another family; alone it would fire on ordinary script traffic. |
| Tool fingerprint | E9 = 0.12 | It answers "which tool", not "who decided". It stays in the main score at low weight and is also reported on its own axis. |
| Reverse evidence | E14, E15 = 0.00 | They must not contribute to the score, only cap it (section 5). |

### 3.2 The E8 gate, stated precisely

Before the rules are evaluated, the engine checks whether any of E1, E2, E3, E4, E5, E6, E11,
E12 has fired. Only if one has is E8 allowed to fire. This is implemented by injecting an
internal `f_core_evidence` flag into the feature dictionary before evaluation.

---

## 4. The noisy-OR fusion, and its algebra

```
score(b) = 1 - prod over the fired rules i of (1 - w_i)
```

The score lies in [0, 1]. With no rule fired it is 0; it approaches 1 as more independent
evidence accumulates, but never reaches it. This is the classic noisy-OR form: it is the
probability that at least one of the evidence items is present, under an independence
assumption.

### 4.1 The three algebraic properties that matter

**Property 1 - a single rule can never convict.**
Among the rules that are usable under the current collection layer, the largest weight is
0.34 (E1). Since `score <= max_i(w_i)` when only one rule fires, a single rule yields at most
0.34, which is below the 0.35 decision threshold. **At least two rules must fire.**

**Property 2 - the minimum number of rules is 2.**
`k_min = ceil( ln(1 - tau) / ln(1 - w_max) )`. With `tau = 0.35` and `w_max = 0.34`:
`k_min = 2`. The value is computed from the live rule table in
`research/engine/evidence.py`; it is a closed-form property of the weights, not a tuned
parameter.

**Property 3 - a single *family* can convict, and this was a correction.**
The family weights, computed as `1 - prod(1 - w)` over the rules of that family:

| Family | Rules | Family weight |
|---|---|---:|
| F5 | E1 | 0.3400 |
| F4 | E2 | 0.1500 |
| F7 | E3 | 0.2400 |
| F10 | E4 | 0.2200 |
| **F3** | **E5, E6, E11** | **0.40864** |
| F6 | E7, E12 | 0.2260 |
| F8 | E8 | 0.2000 |
| F9 | E9 | 0.1200 |

**F3 alone reaches 0.40864, which is above 0.35.** So the honest statement is:

> A single rule can never convict. A single *family* can: if E5, E6 and E11 all fire, the actor
> is convicted on the feedback-adaptivity family alone.

This is a correction, and the earlier claim was wrong. An earlier draft of the project's own
material asserted that no single family could convict either. That assertion was incorrect, and
it was corrected during the study's own methodology review: the draft text read "if only one rule
fires, score <= max w = 0.34 < 0.35, so a single behaviour is never enough", which is true at
rule level but had been carried over to family level without checking. The correction is
recorded in the study's second-round experiment log: *"honest statement: if the original report
says 'neither can a single family convict' that is inaccurate - when the three rules of the F3
family fire together they reach 0.4086 > the decision line."* The corrected statement and the
number are carried forward into the rule table shipped here, and the family weights above are
re-derived directly from it.

### 4.2 E10 is excluded from the algebra

E10 carries weight 0.95, which is above the threshold and would make a single rule sufficient.
It is excluded from every algebraic claim because it is **not computable** under the current
collection layer: the probe family needs response headers, and the capture layer records
neither headers nor bodies. The exclusion is explicit in the study's own code, which filters
`RESP_SIDE = ("E10",)` before computing `k_min` and the family weights.

The same exclusion applies to the reverse-evidence rules E14 and E15: their weight is 0, so they
are not "forward scoring rules" and take no part in the arithmetic.

---

## 5. Reverse evidence: a cap, not a contribution

E14 and E15 identify traffic that is **not** an AI agent:

* **E14 (dictionary brute-force discrimination)** fires when configuration and management paths
  are at least 35% of the actor's requests **and** business 2xx responses are at most 5%. The
  reasoning: an AI agent is sent to verify business vulnerabilities; it does not read
  configuration files. A credential-stuffing scanner does.
* **E15 (dictionary-driven high-frequency enumeration discrimination)** fires when at least 200
  endpoint templates were enumerated, at least 85% of responses were 404, at most 5% were 2xx,
  and the rate is at least 60 requests per minute. That is a dictionary enumerator, not a
  reasoning agent.

**They act as a cap rather than contributing to the score.** Because their weight is 0, the
multiplicative factor `(1 - w)` is exactly 1, so they leave the noisy-OR product untouched.
They cannot raise the score and they cannot lower it. What they do is applied afterwards:

```
if E14 fired or E15 fired:
    score = min(score, 0.25)
```

The cap of 0.25 is below the 0.35 decision threshold, so a capped actor is never flagged. This
is the "veto" recorded in the scoring output as `vetoed` and `veto_reason`, and it is why the
pentest-ai capture (E15 fired: 428 templates in 936 s, 99% 404, 1% 2xx, 442 requests per
minute) scores 0.250 rather than its pre-veto 0.698.

**Why a cap and not a subtraction.** A subtraction would depend on how many reverse-evidence rules
fire and would perturb the score of every actor with a dictionary-shaped request. A cap is
idempotent, order-independent, and leaves every non-vetoed actor's score exactly as the noisy-OR
produced it.

---

## 6. The decision threshold and what it trades

**tau = 0.35.** The calibration is empirical, not chosen for convenience:

| Quantity | Value | Source |
|---|---:|---|
| Highest score among the real-attacker population | 0.7147 | `research/evaluation/false_positive_eval.py` |
| Score of a capped (vetoed) real attacker | 0.2500 | `data/features/actor_features.jsonl` |
| Lowest score among detected AI actors | 0.4146 (AutoPT) | `data/aggregate/framework_detection.json` |
| False-positive rate on 1,582 real attackers at tau 0.35 | 2.718% (95% CI [2.02%, 3.64%]) | `data/aggregate/threshold_fpr_tradeoff.json` |
| Segment recall at tau 0.35 | 13/15 = 86.67% | `research/evaluation/evaluate_detection.py` |
| Framework recall at tau 0.35 | 10/12 = 83.33% | same |
| One-sided 95% lower bound for "all k frameworks detected", k = 12 | 0.7791 | `0.05^(1/12)` |

The threshold sits in a plateau. From `research/evaluation/threshold_sweep.py`:

| tau | segments | segment recall | frameworks | FPR (real attackers) |
|---:|---:|---:|---:|---:|
| 0.20 | 15/15 | 1.0000 | 12/12 | 24.21% |
| 0.25 | 15/15 | 1.0000 | 12/12 | 24.21% |
| 0.30 | 13/15 | 0.8667 | 10/12 | 4.24% |
| **0.35** | **13/15** | **0.8667** | **10/12** | **2.72%** |
| 0.40 | 13/15 | 0.8667 | 10/12 | 2.15% |
| 0.45 | 11/15 | 0.7333 | 8/12 | 1.07% |
| 0.50 | 11/15 | 0.7333 | 8/12 | 0.19% |
| 0.55 | 9/15 | 0.6000 | 6/12 | 0.13% |
| 0.60 | 9/15 | 0.6000 | 6/12 | 0.13% |

Between tau 0.30 and tau 0.40 the recall is flat at 13/15 while the false-positive rate falls
from 4.24% to 2.15%. 0.35 is the middle of that plateau. Pushing to 0.50 buys a 14-fold
reduction in false positives and costs two actor captures and two frameworks.

**Deployment note.** The threshold is a deployment parameter, not a property of the method. A
high-volume environment that cannot tolerate 2.7% may prefer 0.50; the cost is stated in the
table above. A deployment that expects tool-driven agents should not expect any threshold to
help - see `LIMITATIONS.md` section 2.

---

## 7. The three-tier signature taxonomy

The signature layer is separate from the behavioural layer. It answers "which framework sent
this request", not "was this an AI agent". Its rules are graded by what they can support.

| Tier | Meaning | Count | Deployment |
|---|---|---:|---|
| **T1** | Framework-exclusive. Zero hits on 9,905,794 public internet requests and zero on 142,705 real WAF attack transactions. | 272 | Can be deployed and alerted on alone |
| **T2** | Attack evidence. Proves that a tool is attacking, but does not distinguish an AI agent from a script. | 126 | Only in combination with other conditions |
| **T3** | Withdrawn: generic tooling identities, generic request headers, non-target-side fields, and literals that cannot occur in real traffic. | 212 | Not for deployment against internet-facing assets |

Tier-1 field distribution: request body 150, request path 37, HTTP request header 36, User-Agent
35, other (TLS, proxy, credential) 12, OAST domain 2.

### 7.1 The rule-usability screen

Before a literal is even considered for a tier, it is screened for whether it could plausibly
appear in real traffic at all. The screen has three outcomes and is implemented in the study's
rule builder (`rule_usability`):

| Outcome | Meaning | Effect |
|---|---|---|
| `dead` | The literal is a **source-code template**, **descriptive text**, or a **placeholder token** - it cannot occur in a real request | demoted to T3 |
| `generic` | The literal is **generic content**: weak credentials, command templates, identifier lists, prototype-pollution payloads - a human attacker sends the same thing | demoted to T2 |
| `ok` | The literal is a specific, unique traffic literal | eligible for T1, subject to real-traffic qualification |

The concrete patterns the screen rejects:

| Category | Examples rejected | Why it cannot be a signature |
|---|---|---|
| Source-code templates | `{name[0]}`, `f"`, `b"`, `def foo`, `class Bar`, `self.`, `import os`, `%(name)s` | These are Python source fragments, not HTTP bytes. A rule built on them would match the framework's *code*, not its *traffic*. |
| Placeholder tokens | `{placeholder}`, `{token}`, `{id}` | The framework's own credential templates, unresolved. AIDA is the clearest case: its substitution regex only matches uppercase letters, digits and underscores, so a lowercase placeholder is sent to the target verbatim. |
| Example hostnames | `attacker.com`, `example.com`, `yourdomain`, `target.com`, `victim.com`, `myserver`, `testphp.vuln`, `YOUR_`, `your_` | Documentation placeholders that the LLM is expected to substitute. A rule on them matches nothing. |
| Descriptive text | Any literal containing CJK characters; `...` / the ellipsis character; full-width punctuation | Comments and prose accidentally carried into the candidate list. |
| Weak credentials | `admin:admin`, `admin/password`, `root/root`, `test/test`, `guest/guest` and the generic `user:password` shape | Real attackers and ordinary clients send these. |
| Identifier lists | Three or more alternatives that are all bare identifiers (`ORG_A_ID`, `Bearer <victim_token>`, `doesnotexist_<unix-ts>`) | A list of candidates, not a single fixed literal. The framework fills them in at runtime. |
| Command templates | `\| nc`, `\| curl`, `\| wget`, `\| bash`, `\| sh`, `\| python`, backtick spans, `$(...)` | Shell pipelines from a prompt template, not request bytes. |
| Prototype-pollution payloads | `__proto__`, `constructor`:, `prototype` | A generic attack technique. Any human attacker or scanner sends the same. |
| Generic header names | `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `Accept`, `Content-Type`, `Accept-Language`, `Upgrade-Insecure-Requests`, `Sec-Fetch-User`, `CloudFront-Viewer-Country` and 40+ more | Sent by every client, and some by every CDN. A rule on a bare header name matches most of the internet. |
| Generic tool user agents | `curl/`, `python-requests`, `Go-http-client`, `Wget/`, `sqlmap`, `ffuf`, `gobuster`, `nuclei`, `nikto`, `masscan`, `Java/` | Public tools. `curl/8.23.0` appeared on 32 of the 999 published scanner records. |
| Public crawler and browser identities | `Googlebot`, `Bingbot`, `YandexBot`, `AhrefsBot`, and complete Chrome desktop user agents | Any client can claim them. |
| Public OAST service domains | `*.oast.fun`, `*.oast.pro`, `interact.sh` | Shared by thousands of projects. |
| Over-short bare words | Length <= 6 with no separator, e.g. `cyber` | 170 real public requests carried the token `cyber`. |
| Multi-alternative rules containing a generic alternative | e.g. `X-Forwarded-Host / Referer / User-Agent / correlation ID` | Every request carries a `User-Agent` header, so the whole rule matched **9,453,473 requests across 74,600 source addresses** before the alternatives were screened individually. |

That last row is the reason the screen checks **each alternative of a multi-alternative rule
individually** rather than the concatenated string: a rule whose alternatives are all generic is
not a generic rule, it is a rule that matches the internet.

### 7.2 The three automated gates that a rule set must pass

1. **Synthetic benign-request self-test.** A realistic Chrome 120 browser request (Windows 10,
   `Accept: text/html`, `Accept-Language`, `Sec-Ch-Ua`, `Sec-Fetch-*`, a `Cookie`) is matched
   against every tier-1 rule with the final deployed regular expression. Any tier-1 hit fails
   the rule and it is demoted automatically. Current status on the released 272-rule tier-1 set:
   **0 hits** (`python -m research.ci.selftest_rules`). At the earlier 450-rule tier-1 count of
   the study the same gate reported 0 hits as well. This gate has caught real defects: on one review it stopped 11
   rules, including a pure-numeric constant that had been wildcarded into `[0-9]+` (which then
   matched any request containing a number), braces that had been treated as placeholders
   (`{7*7}` became "match anything"), bare-star alternatives that degenerated to "match
   everything", and generic header names. The count of 11 refers to that review, at a larger
   tier-1 population than the one released.
2. **Real-traffic qualification.** The rule set is scanned against 9,905,794 real public internet
   requests with full headers and bodies, and separately against 142,705 real WAF attack
   transactions. Tier-1 hits must be zero on both.
3. **Scanner hard-negative qualification.** The rule set is scanned against real scanner traffic
   produced by sqlmap, nmap http-enum, gobuster and curl against the evaluation target.
   Tier-1 hits must be zero, and the behavioural layer must not classify a scanner as an agent.

The released repository re-runs gates 1 and 3 on the shipped data:
`python -m research.ci.selftest_rules`.

---

## 8. The signature layer and the behavioural layer are orthogonal

Three axes, measured separately and never summed:

| Axis | Question | Where it lives |
|---|---|---|
| Maliciousness | is this request an attack? | F11 payload semantics; reported as `maliciousness_axis` |
| AI-ness | is an agent deciding? | the main noisy-OR score of section 4 |
| Tool-ness | which tool is being used? | F9 tool fingerprint; reported as `tool_axis` |

`tool_axis = min(1, f9_ua_families / 4 * 0.7 + min(1, f9_ua_switch_rate * 2) * 0.3)` and
`maliciousness_axis = min(1, f11_payload_kinds / 5 * 0.7 + min(1, f11_payload_density * 3) * 0.3)`.

Keeping them separate is not a stylistic choice. The study's own measurement is that **the more
attack-like the payload, the more likely the traffic is a script**: in one 541-request agent
round, 371 responses were 404 and the injection payload hit count was **zero**, while a 10-line
fixed self-test script produced the sqli, xss and ssrf hits. A single-axis detector would have
scored the script higher.

---

## 9. The shared matching module

`research/engine/ioc_match.py` is the **single authoritative implementation** of signature
matching. The rule generator, the validator, the exporter and the self-tests all call it:

```python
deploy_regex(rule)  -> str            # the deployed expression
compile_rule(rule)  -> (regex, field) # compiled, cached
match_sample(rule, sample) -> bool    # match one request sample
```

### 9.1 Why one implementation rather than several

Two defects occurred before this module existed, both caused by the generation semantics and the
validation semantics being different code:

1. **The deployed platform files were empty rules.** The syntax function was handed a rule
   dictionary with a `pattern` field but read a `value` field instead, so every rule serialised
   to an empty string. The self-check at the time **counted** the rules and never looked at
   their content, so it passed. The fix was to use one field, plus a write-time check that aborts
   if any empty rule is about to be written.
2. **Literals were compiled as regular expressions.** A literal containing `*` or `[` was
   treated as a regular expression, so `cs*` matched "c followed by zero or more s" rather than
   the literal four characters. The validator compiled the raw literal while the deployed file
   used an escaped expression, so the two did not agree and a rule could pass validation and
   never fire in production.

A third, related defect was that **regular-expression metacharacters were incompatible with the
target platforms**: Lucene and KQL have no `\s` operator, and in Suricata's `pcre:` an
unescaped `/` terminates the expression early. The module resolves both by rewriting `\s` to
`[ \t]` in character classes and escaping the forward slash.

### 9.2 The matching semantics it defines

* `match = regex`: the expression computed at generation time is used verbatim, already
  `re.escape`d, with the angle-bracket placeholder written as `[^\s/]+`.
* `match = exact`: the literal is split on ` / ` into alternatives, each alternative's `*` is
  rewritten as the placeholder `[^ \t/]*`, and each alternative is `re.escape`d. Alternatives are
  combined into `(?:a|b)`.
* All expressions are compiled with `re.IGNORECASE`.
* The field a rule applies to is derived from its kind: `UA` -> `user_agent`, `PATH` -> `uri`,
  `PAYLOAD` and `CRED` -> `body`, `HEADER` -> `header`, `OAST` -> `oast_dns`.
* Compilation is cached by rule identity; without the cache, rescoring the same rule object is
  about 100 times slower.

### 9.3 Why one implementation is a correctness property, not a convenience

If the generator and the validator disagree about what a rule means, then every number the
validator produces is a statement about a different rule set than the one that will be deployed.
The two defects above were both of exactly this kind, and both would have been caught
immediately by a single implementation with a shared test. The module exists so that "the rule
that was validated" and "the rule that is deployed" are the same object by construction.

---

## 10. Reproducing the detector

```bash
cd ai-agent-attack-signatures

# segment a capture into behavioural actors
python -m research.pipeline.actor_segmentation --input data/positive/DSH-1/access.jsonl --out out/actors.jsonl --mode session

# score the actors
python -m research.pipeline.score_actor --actors out/actors.jsonl --out out/scores.jsonl

# or do both in one step over a directory of captures
python -m research.pipeline.score_actor --input data/positive --out out/actor

# evaluate
python -m research.evaluation.evaluate_detection
python -m research.evaluation.false_positive_eval
python -m research.evaluation.lofo
python -m research.evaluation.family_ablation
python -m research.evaluation.threshold_sweep

# signature self-tests
python -m research.ci.selftest_rules
python -m research.ci.check_headline_numbers
```

Runtime expectations: the whole evaluation suite over the 15 published captures and the 1,582
attacker actors runs in a few seconds on one CPU core; no GPU, no network and no third-party
package is required (SciPy is used when present and a pure-Python Beta quantile is used when it
is not, verified equivalent to 1e-12).

---

## 11. Code map

| Module | Role |
|---|---|
| `research/engine/capture.py` | request event model and access-log reader |
| `research/engine/config.py` | feature-family switches, thresholds, noise-filter settings |
| `research/engine/segment.py` | noise removal, actor/session segmentation, sliding windows |
| `research/engine/features.py` | feature families F1-F13 |
| `research/engine/evidence.py` | evidence rules E1-E15, the noisy-OR score, the veto |
| `research/engine/ioc_match.py` | the single authoritative signature matching implementation |
| `research/engine/ground_truth.py` | actor labels used for evaluation only, never as features |
| `research/engine/evaluate.py` | confusion matrix, ROC/PR, Wilson interval, cluster bootstrap |
| `research/pipeline/actor_segmentation.py` | actor segmentation CLI |
| `research/pipeline/feature_extraction.py` | feature extraction CLI |
| `research/pipeline/score_actor.py` | scoring CLI |
| `research/evaluation/` | the five evaluation scripts |
| `research/ci/` | the headline-number check and the signature self-tests |
