# Limitations

This document states what the study does **not** establish. Every number here is read from the
shipped artefacts; the source is given with each claim.

---

## 1. The central finding: an agent that delegates is not distinguishable from a human running the same tool

> **When an AI penetration agent hands the actual attack to general-purpose tooling
> (sqlmap, ffuf, nuclei, curl), the traffic arriving at the target is information-theoretically
> indistinguishable from a human running the same tool.**
>
> Passive HTTP behaviour detection cannot separate the two, and neither can the signature layer:
> the tool's user agent is a generic public identifier.

Three independent pieces of evidence support this. They come from different frameworks, different
experimental setups and different data sources, which is what makes the claim robust.

### Evidence 1 — AutoPT delegating to sqlmap

Source: `data/positive/AutoPT-1/meta.json`, the capture's own user-agent histogram, and the
study's second-round experiment log.

| Measurement | Value |
|---|---|
| Requests issued by the agent against the target | 4,530 (94 seconds) |
| Requests carrying `sqlmap/1.10.4#stable` | 3,114 |
| Requests carrying the agent's own user agent `AutoPT/1.0` | **1** |
| Path templates enumerated | 12 |
| Rate | 2,891 requests per minute |
| Status codes | 99.6% 404/422/429, essentially no 2xx feedback |
| Rules fired | E6, E9, E11, E12 |
| Rules **not** fired | E5 (needs 2xx/401 feedback), E7 (identity lineage), E2 (needs a long span) |
| AI attribution score | **0.415**, above the 0.35 threshold |

The agent's own identity appears once in 4,530 requests. The target sees sqlmap. The score
clears the threshold, but only on **edge evidence** - branch pruning, 404 tolerance and
back-tracking - not on anything resembling an "AI feature". A human driving sqlmap produces the
same bytes.

### Evidence 2 — six independent scanner containers producing 66.67% false positives

Source: `data/negative/_index.json` and `data/aggregate/threshold_fpr_tradeoff.json`.

Ten real scanning tools were placed in twelve independent containers, each with its own source
address on the evaluation target's network, so that each container is a separate behavioural
actor with both successful and failed responses. The captured traffic holds 12,666 requests, of
which 1,084 are 2xx and 11,488 are 4xx.

At the shipped threshold of 0.35, **4 of the 6 attacker-class scanner actors are flagged -
66.67%** (Wilson 95% interval [30.0%, 90.3%]).

**What this figure characterises, stated precisely.** The released scanner negative set is
**ffuf-dominated**: of the 999 published records, **910 carry `Fuzz Faster U Fool v2.1.0-dev`**.
The remaining 89 are curl (35), python-requests (13), masscan (6), Nikto (6), browser-masquerade
user agents (27), Go-http-client (2) and wget (2). No gobuster, nuclei, dirb or nmap record
survives into the released set; in the full 12,666-record source capture sqlmap contributes a
single request. **The 66.67% therefore measures the false-positive behaviour of ffuf-style
enumeration against this detector, not of a balanced multi-tool scanner population.** A different
enumeration tool could score differently. The sample is 6 actors, so the interval is wide.

### Evidence 3 — pentest-ai degrading to dictionary enumeration

Source: `data/positive/pentest-ai-1/meta.json`.

pentest-ai is an unusual case: its own user agent `pentest-ai/1.6.2 (compatible; rv:<12hex>;
+https://pentestai.xyz)` is present on 100% of its 6,888 requests - an ideal signature-layer
indicator. Its *behavioural* score is **0.250**, below the threshold. The reverse-evidence rule
E15 explains why: in 936 seconds it enumerated 428 endpoint templates at 99% 404 responses, 1%
2xx responses and 442 requests per minute. That is dictionary enumeration, and E15 caps the
score at 0.25.

The cause is the framework's own configuration (`--scope web --intensity safe`). At low
intensity the agent behaves like a dictionary rather than like a reasoning loop.

**The three cases together:** the behavioural layer works exactly when the agent is doing
"adjust the next step in response to the previous response". When it mechanically executes a
preset sequence - or hands the work to a tool - it and the tool are the same thing from the
target's side.

---

## 2. Raising the threshold does not help against tool-driven traffic

Source: `data/aggregate/threshold_fpr_tradeoff.json` and `data/negative/_index.json`.

| Threshold | Segment recall | Framework recall | FPR, real attackers | **FPR, scanner-type actors** |
|---:|---:|---:|---:|---:|
| 0.30 | 0.923 | 9/10 | 4.24% | **66.67%** |
| **0.35** | 0.923 | 9/10 | 2.72% | **66.67%** |
| 0.40 | 0.923 | 9/10 | 2.15% | **66.67%** |
| 0.50 | 0.846 | 8/10 | 0.19% | **66.67%** |
| 0.55 | 0.692 | 6/10 | 0.13% | 50.00% |
| 0.60 | 0.692 | 6/10 | 0.13% | 0.00% |

The scanner false-positive rate is **flat at 66.67% from tau 0.30 to tau 0.50**. The reason is
structural, not a calibration defect: the scanner actors fire the *same forward rules* as the AI
agents (E5, E6, E7, E9, E11, E12), so raising the threshold removes them and the agents
together. Only at tau 0.60 does the scanner rate reach zero, at the cost of dropping framework
recall from 9/10 to 6/10.

There is a second, independent obstruction. Rule E12 ("after a 2xx, revisit the same endpoint")
appears to have 0% coverage on the real-attacker population, which would suggest it as a
discriminator. **That zero is a measurement artefact.** The WAF audit log records only
transactions that triggered a WAF rule; successful responses are not in it, so E12's 2xx
denominator is identically zero and the rule cannot fire. Re-measured on the negative
populations that *do* contain successful responses, E12 fires on **6 of 6** of the released
scanner actors and on **8 of 8** actors of the full source file.
E12 is not a discriminator, and no E12 gating is used anywhere in this release.

---

## 3. Passive HTTP alone is insufficient: the reliable signal is outbound

The behaviour layer fails precisely where the agent delegates. What does not change is the
agent's *own* requirement: **to reason, it must call a model.** Every AI penetration agent
therefore produces outbound traffic to an LLM gateway, and that traffic is the agent's, not the
tool's.

Conceptually the rule is:

> If a source address that is producing attack traffic against the target also produces
> outbound connections to known LLM inference endpoints, and the timing of those outbound
> connections brackets the attack, then the source is an automated agent, regardless of whether
> the inbound requests carry a framework fingerprint.

The pieces needed to make it operational:

| Requirement | Why it is needed |
|---|---|
| Egress logs at the attack source's egress point | The signal does not exist in inbound-only logs |
| A list of LLM inference endpoints (hostnames, and for TLS the SNI or the JA3/JA4 fingerprint) | The gateway is usually reached over TLS, so the hostname may only be visible in SNI or in the certificate |
| Timestamp correlation between outbound and inbound | Attribution is temporal; a source address that talks to an LLM gateway and attacks a target in the same window is a different situation from one that does neither |
| Care with shared infrastructure | Cloud provider metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) and public OAST services are not LLM endpoints and must not be counted as such |

The study's rule E8 is the in-band version of this idea, and it is deliberately weak: it fires
only if another family has already produced evidence, and it is worth 0.20 of the score. Its
founder, `f8_egress_*`, is **structurally zero for all 1,582 real-attacker actors**, because
the WAF log records inbound transactions only. The zero is a property of the instrumentation, not
an observation about the attackers.

The complete deployment form is therefore **passive HTTP behaviour detection plus attack-source
egress correlation**: the first covers agents that issue requests themselves (the majority of
the 15 positive captures), the second covers agents that delegate to tools.

---

## 4. Blind spot: light-weight, direct-request agents

Source: `data/aggregate/framework_detection.json`.

| Framework | Score | Rules fired | Requests | Duration (s) | Distinct UA families |
|---|---:|---|---:|---:|---:|
| hackingBuddyGPT | 0.2800 | E5, E12 | 62 | 268 | 1 (`python-requests/2.34.2`) |
| pentest-ai | 0.2500 | E1, E5, E6, E7, E11, E12, E15 (veto) | 6,888 | 936 | 1 (`pentest-ai/1.6.2`) |

**The mechanism.** The behavioural layer measures evidence of a *reasoning loop*: scale, breadth,
feedback-driven adaptation, identity rotation, multi-channel orchestration. A light-weight agent
that issues single requests through one HTTP library produces almost none of that evidence:

1. **One user-agent family.** The tool-fingerprint axis is 0.175 for hackingBuddyGPT, against
   1.000 for strix. E9 (multi-channel orchestration) cannot fire.
2. **Small volume and short duration.** 62 requests over 268 seconds cannot reach the scale
   thresholds in E1 (duration > 900 s, >= 40 templates) or E2 (a long pause).
3. **No error-feedback loop.** Most responses are 2xx, so E5 (route change after error) and E11
   (404 tolerance) never fire.
4. **No identity structure.** One identity, so E3 and E4 never fire.

Note that both misses are *detectable by the signature layer*: pentest-ai's user agent is on
100% of its requests. The failure is confined to the behavioural layer. That asymmetry is the
argument for running both layers.

---

## 5. Statistical limitations

### 5.1 The negative set is dominated by one dataset that contains no successful responses

Source: `data/negative/README.md`, `data/features/README.md` and
`data/features/actor_features.jsonl`.

| Negative source | Requests | Actors | Contains 2xx? |
|---|---:|---:|---|
| N1 honeypot field data (armbian v1+v2) | 10,788 | 91 | yes (749 2xx) |
| N2 ModSecurity 30-day WAF hits | 151,011 | 2,794 | **no (0 2xx)** |
| N3 real scanners against the evaluation target | 9,833+ | 8 | yes (868 2xx) |

The 1,582-actor population used for the headline false-positive rate is drawn entirely from N2.
N2 contains **no successful responses at all**, because a WAF audit log only records
transactions that triggered a WAF rule. Three consequences:

* **Features that depend on successful responses are under-tested.** E12 (`f6_verify_backtrack`)
  can never fire on this population. Its measured 0% negative coverage is an artefact, and the
  8-of-8 result on the scanner population shows the rule is not a discriminator.
* The 8 `f8_egress_*` features are identically zero for the same reason.
* The 1,378 "browser" actors of N2 are attacker-classified by their user-agent blob; a browser
  user agent on an attack transaction does not mean a human was operating it.

### 5.2 1,582 negative actors is a small sample for a sub-1% claim

Source: `research/evaluation/stats.py`, `data/aggregate/threshold_fpr_tradeoff.json`.

At tau 0.35 the measured false-positive rate is 2.718% with a Wilson 95% interval of
[2.02%, 3.64%]. To support a claim of FPR < 1% from a *zero* count, 300 independent actors are
required; for FPR < 0.1%, 3,000. The present population of 1,582 supports the 2.72% figure
with a useful interval, and does not support anything below roughly 1%.

The earlier claim in this project's own reporting that "FPR < 5.36%" (rule of three over 56
actors) was **withdrawn and replaced** when the negative population was enlarged. The
replacement number, 2.72%, is larger and better founded. The general lesson is that a
false-positive rate quoted without its denominator and interval is not a measurement.

### 5.3 The positive corpus is 15 captures from 12 frameworks

Source: `data/aggregate/framework_detection.json`.

The generalisation claim "all *k* frameworks are detected" has one-sided 95% lower bound
0.05^(1/12) = **0.779**. That is the honest strength of the claim. Two consequences:

* The corpus is **clustered, not independent**: three captures come from one framework (DSH) and
  two from another (PentAGI). Treating 15 captures as 15 independent Bernoulli trials would give
  a spuriously narrow interval. The framework-level bound is the correct statement; the
  segment-level Clopper-Pearson interval [0.5954, 0.9834] should be read with that clustering
  in mind.
* **Adding captures of an already-seen framework does not strengthen the generalisation claim.**
  Adding a new framework does. The bound as a function of framework count: k = 8 gives 0.688,
  k = 12 gives 0.779, k = 20 gives 0.861.

The 12-framework corpus also covers three implementation languages (Go, Python, TypeScript) and
three attack shapes (sandboxed execution, AI-driven scanner, light-weight direct request), which
is the main source of its diversity.

### 5.4 What the leave-one-framework-out result does and does not show

Nine of ten archived folds are detected. The failing fold, hackingBuddyGPT, fails because when
it is held out the calibration threshold rises to 0.4146 while its score is 0.2800. This
demonstrates that the detector **can** generalise to an unseen framework, but on 10 folds it does
not establish how often it will. The current corpus recomputation gives 11 of 12, with
pentest-ai as the only failure, for the same structural reason.

### 5.5 The signature validation covers only two request fields on the WAF data

Source: `data/aggregate/rule_validation_counts.json`.

Of the 142,705 WAF attack transactions, 0 carried a request body - the audit log format does not
record bodies. The 150 body-field tier-1 rules could therefore **not** be exercised against
real attack traffic at all. Their zero-hit result comes from the 9.9M-request public traffic
scan, which does carry bodies. This is a gap in the evidence, not a clean pass.

---

## 6. Disclosure risk: publishing this makes evasion cheaper

**Publishing this material makes evasion cheaper, and the authors accept that trade-off.**

What an operator gains from reading this repository:

* The exact user agents, header names, paths and payload literals that constitute the tier-1
  signatures. Changing a user agent defeats a signature.
* The rule conditions and their thresholds, so the score can be computed offline and suppressed
  by construction: the minimum set of behaviours that still clears 0.35 is derivable from
  `METHODOLOGY.md`.
* The false-positive structure: which rules fire on ordinary attackers (E5, E6, E11, E12) and
  which do not (E3, E4, E9), and therefore which behaviours to drop.

What this costs the defensive side, concretely: a tier-1 signature set that is published is a
signature set that decays. The study's own evidence for this is that 7 of the rules added in the
expansion round (from 38 to 65 codebases) matched real public traffic and had to be demoted -
generic Chrome-masquerade user agents, `Python/3`, the bare token `cyber`, a public Googlebot
user agent, a `True-Client-IP` private-address forgery, and public OAST domains. Their hit
counts on the shipped corpus are in `RESULTS.md` section 6.2.
Static source audit cannot find those failures; only a large real-traffic scan does.

Why the trade-off is accepted anyway:

1. **The unpublishable alternative is worse.** The signature sets and the detection method
   either circulate or they do not. A method that only the study team can run protects nobody
   outside the team.
2. **The finding that matters is negative.** "Most AI agents are indistinguishable from a
   human running the same tool" is a statement about the *absence* of an attribution surface. It
   cannot be exploited in the way a rule list can; it tells operators where not to spend effort.
3. **The framework-level attribution surfaces are inherently shallow.** 10 of 64 audited
   frameworks have one. Even unpublished, they rot: one user-agent change and a signature dies.
   `THREAT_MODEL.md` describes the maintenance model that addresses this, and asks framework
   authors to submit and confirm their own signatures - which is a strictly better channel than
   an attacker reading a rule dump.

Read `THREAT_MODEL.md` before deploying anything from this repository.

---

## 7. Summary of what this study does and does not establish

| Claim | Status | Evidence |
|---|---|---|
| Tier-1 signatures do not fire on real internet or real attack traffic | **Supported** | 0 hits on 9,905,794 requests / 80,987 source addresses; 0 hits on 142,705 WAF transactions |
| An actor-level behavioural detector separates AI agents from ordinary internet attackers | **Supported** | 2.72% FPR (95% CI [2.02%, 3.64%]) on 1,582 real attacker actors; 13/15 segment recall |
| The detector generalises to an unseen framework | **Weakly supported** | 9/10 archived LOFO folds, 11/12 recomputed; framework-level lower bound 0.779 |
| The detector separates AI agents from tool-driven attackers | **Not supported** | 66.67% false positives on the scanner population; flat from tau 0.30 to 0.50 |
| A signature catalogue identifies which AI framework attacked | **Supported for 10 of 64 audited frameworks** | `FRAMEWORK_COVERAGE.md` |
| The false-positive rate is below 1% | **Not established** | 1,582 actors support 2.72% [2.02%, 3.64%]; < 1% needs 300 actors from a zero count |
| E12 distinguishes AI agents from scanners | **Refuted** | 6/6 released scanner actors (8/8 of the full source file) fire it; the 0% figure is a log artefact |
| Passive HTTP detection alone is sufficient | **Refuted** | `LIMITATIONS.md` section 3 |
