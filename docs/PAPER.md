# Attribution Limits of AI Pentest Agents

## An Empirical Study of 65 Audited Codebases, 272 Validated Traffic Signatures, and the Boundary Where Attribution Stops Working

**Repository:** `ai-agent-attack-signatures`  
**Artifact:** signatures, datasets and evaluation code in this repository

---

## Abstract

AI-assisted penetration-testing agents are being deployed to automate reconnaissance and
exploitation at scale. The defensive question that follows is whether such traffic can be
identified and attributed on the victim network. This paper reports an empirical study of
65 audited AI-pentest codebases (64 third-party frameworks plus one in-house implementation),
combining static source auditing with live traffic collection and
scoring against three real-world corpora.

We extract 610 traffic signatures from the audited frameworks and tier them by
attributability: 272 are framework-exclusive and observable in an HTTP access log (T1), 126
express generic attack semantics that a human attacker produces as well (T2), and 212 are
generic tooling identifiers or over-broad patterns that must not be used for attribution (T3).
The T1 set is validated against 9,905,794 public internet requests from 80,987 distinct
source addresses and against 142,705 real WAF attack transactions spanning 30 days; it
matches **zero** rules in both corpora. A combinatorial criterion over the same corpus flags
exactly one source address.

Alongside signatures we build a behavioural detector whose decision unit is the *actor*
(all requests from one source address within a time window) rather than the individual
request. Forty-three features grouped into ten families feed fourteen evidence rules that
are fused with a noisy-OR model. Across 15 live AI-agent captures covering 12 frameworks the
detector reaches 86.7% segment recall and 83.3% framework recall (one-sided 95% lower bound
0.779), while a leave-one-framework-out evaluation retains 90% recall. On 1,582 real
attacker actors the false-positive rate is 2.72% (95% CI [2.02%, 3.64%]).

The central negative result is that **attribution and detection are different problems, and
neither is solved by signatures alone**. An agent that delegates to sqlmap, ffuf or nuclei
is indistinguishable from a human running the same tool: on six scanner actors the
false-positive rate is 66.67% and raising the decision threshold does not help. We
quantify this boundary with three independent pieces of evidence, and show that the only
reliable attribution signal for an AI agent is its outbound traffic to an LLM gateway -
which requires egress logs, not passive inspection. We release the signatures, the
captured datasets and the evaluation code so that the measurements can be reproduced and
extended.

---

## 1. Introduction

AI pentest agents promise to compress the reconnaissance and exploitation phases of an
assessment into a single supervised loop. They are actively being integrated into CI
pipelines, bug-bounty triage and continuous penetration testing. The defender's question is
concrete: given a stream of HTTP requests to a protected asset, can we tell that they were
produced by an AI agent rather than by a person - and if so, which agent?

Signature catalogues exist for conventional tooling, and the obvious move is to apply the
same recipe to AI agents: read the source, extract the distinguishing strings, ship the
rules. This paper reports doing exactly that for 65 codebases, and then measuring how far
the result actually gets on real traffic.

Three findings shape the contribution.

**Finding 1 - the majority of AI agents leave no framework-specific trace on the target.**
Most frameworks do not issue HTTP requests themselves; they orchestrate external tools
(sqlmap, ffuf, nuclei, nmap, curl) through a shell. The target therefore observes the
tool, not the agent. Of 65 audited codebases, only 10 were validated end-to-end as
attributable on the target side. A signature set built naively from source code would
mostly encode strings that never reach a victim.

**Finding 2 - source-code signatures need real-traffic qualification, and static analysis
cannot supply it.** Several strings that look like strong fingerprints are ordinary client
behaviour: a browser-disguise User-Agent, a bare `Python/3`, a `True-Client-IP` header
carrying a private address, a public out-of-band-interaction domain. Each was verified by
replaying the full rule set against 9.9 million real requests; the surviving T1 set matches
nothing in either real corpus.

**Finding 3 - attribution is not detection.** Even perfect framework attribution does not
answer the operational question. We measure the false-positive rate of a behavioural
detector on 1,582 real attacker actors (2.72%) and separately on six scanner actors
(66.67%), and show that the latter is not a threshold-tuning problem: tool-driven traffic
and agent-driven traffic overlap in exactly the dimensions the detector measures.

The contributions are:

1. A source-audited corpus of 65 codebases (64 third-party frameworks plus one in-house
   implementation) with a per-framework attribution
   matrix (Section 6).
2. A tiered signature set of 610 rules with a documented derivation procedure, a
   rule-usability screen, and zero hits on two real corpora (Sections 5.5 and 7.1).
3. An actor-level behavioural detector with an explicit fusion model and an algebraically
   characterised decision rule (Sections 5.1-5.4).
4. A quantified account of the attribution boundary, with three independent pieces of
   evidence, and the deployment guidance that follows from it (Sections 8 and 9).
5. A released dataset and evaluation code, so every number in this paper can be recomputed
   (Section 10).

---

## 2. Related Work

**Tool fingerprinting.** Signature-based attribution of security tooling is long established
in the honeypot and IDS literature. The problem this paper inherits is well known:
signatures derived from tool source code frequently match benign traffic, and the standard
remedy is empirical qualification against real captures. Our contribution here is to apply
that remedy at corpus scale and to report the resulting attrition explicitly, because the
attrition is the interesting result rather than an implementation detail.

**Attack detection.** Behavioural approaches to attack detection group requests into
sessions and score them against behavioural evidence. Our detector follows that line, with
two departures: the decision unit is the actor (source address plus time window) rather
than the session, and the evidence model is a noisy-OR with reverse evidence acting as a
cap rather than as a negative contribution.

**LLM agent detection.** Recent work distinguishes LLM-generated content from human content
in application-layer payloads. That setting is different in kind: the payload itself is the
signal. Here the interesting surface is *request behaviour* - the pattern of what an agent
probes next given what came back - which is a much weaker signal than lexical markers.

**AI pentest frameworks.** Numerous open-source AI pentest agents have appeared since 2023.
They are typically evaluated on task success against vulnerable applications. That
evaluation is orthogonal to this work: we ask what the traffic looks like from the target
side, including when it looks like nothing distinctive at all.

---

## 3. Threat Model and Problem Definition

### 3.1 Adversary setting

The adversary is an operator running an AI pentest agent against a protected asset. The
operator may be malicious. The agent may be one of the frameworks studied here, a
commercial product, or an in-house variant; the defensive measures must not assume any of
them.

The defender operates a passive HTTP inspection point (reverse proxy, WAF, IDS) and may
additionally have egress logs from the same network segment.

### 3.2 Objectives

| | Objective |
|---|---|
| **O1 (attribution)** | Given HTTP requests, determine which AI framework produced them |
| **O2 (detection)** | Given HTTP requests, determine whether an AI agent produced them |
| **O3 (operational)** | Keep the false-positive rate low enough to be deployable |

O1 and O2 are distinct. A signature set addresses O1 only. O2 requires behaviour. Most of
the literature conflates them, which is one reason agent traffic is hard to operationalise.

### 3.3 Non-goals

We do not attempt to detect an agent's *outbound* traffic to LLM providers; we describe it
in Section 8.3 as the recommended complementary control but do not evaluate it. We do not
evaluate the frameworks' attack effectiveness. We do not claim the signature set is
exhaustive for any framework - it reflects the audited revision, and Section 9 discusses
maintenance.

---

## 4. Evaluation Corpora

| Corpus | Purpose | Size |
|---|---|---|
| **Framework corpus** (source) | Signature extraction | 65 repositories |
| **Live agent captures** (positive) | Detection evaluation | 15 actors / 12 frameworks / 211,547 requests |
| **Scanner captures** (negative) | Hard negative for tool-driven traffic | 6 actors / 999 requests |
| **Public internet traffic** | Rule false-positive validation | 9,905,794 requests / 80,987 source addresses |
| **WAF attack log** | Rule false-positive validation on attacks | 142,705 transactions / 30 days |
| **Real attacker actors** (negative) | Behavioural false-positive evaluation | 1,582 actors |

The two large corpora are used only to qualify signatures. The behavioural detector is
evaluated on the live captures and on the two actor-level negative sets.

---

## 5. Methodology

### 5.1 The decision unit: the actor

A single HTTP request carries very little evidence. `curl/8.23.0 GET /admin` is produced by
a human running curl, by a framework that shells out to curl, and by a vulnerability scanner
with the same defaults. Evidence accumulates only across a sequence of requests, so the
detector operates on the **actor**:

> An actor is the set of all requests from one source address within one time window.

Two consequences follow. First, the alert unit becomes the source address rather than the
request, which is what an operator can actually act on. Second, the false-positive rate is
measured over actors, not requests - a request-level false-positive rate would be
misleading by construction, since one noisy actor generates many requests. Every
false-positive number in this paper is actor-level.

The actor segmentation, the time-window length and the source-address grouping are
implemented once and shared by the collector, the feature extractor and the evaluator, so
that no measurement can drift between components.

### 5.2 Feature families

Forty-three features are extracted from each actor's request sequence and grouped into ten
families (the shipped engine exposes 103 named features across 11 families). The families are designed so that a family failure is diagnosable: each one
isolates a different dimension of agent behaviour.

| Family | Dimension | Representative features |
|---|---|---|
| F3 | Post-error behaviour | error-to-endpoint-family switch rate, invalid-branch pruning rate, 404 tolerance |
| F4 | Breadth | distinct endpoint templates, distinct URL path segments |
| F5 | Exploration scale | endpoint templates per unit time, 4xx ratio, 2xx ratio, request rate |
| F6 | Enumeration and verification | ids enumerated per template, re-visit rate after a 2xx |
| F7 | Identity lineage | distinct identities used, unauthenticated ratio, identity churn |
| F8 | Session structure | requests per identity, parameter diversity |
| F9 | Execution channels | distinct User-Agent families in parallel use |
| F10 | Payload shape | request-body length distribution, content-type diversity |
| F13 | Dictionary-driven discrimination | configuration-path ratio (used as reverse evidence) |

Section 7.5 reports the ablation over these families.

### 5.3 Evidence rules

Fourteen evidence rules are implemented: twelve positive (E1-E12), two negative (E14, E15).
The identifier E13 is retired - it was rejected on real traffic - and E10 is a response-side
rule that cannot be computed from request data alone. Each rule carries a weight w that
expresses how unlikely it is that a human produces the observed pattern - it is a
diagnostic-likelihood ratio expressed as a prior-odds adjustment, not an accuracy claim.

Representative rules:

| Rule | Weight | Condition | Family |
|---|---:|---|---|
| E1 | 0.34 | explores many endpoint templates, continues despite a high 4xx ratio | F5 |
| E5 | 0.20 | after repeated errors, switches to a different endpoint family | F3 |
| E6 | 0.16 | abandons an invalid endpoint family entirely | F3 |
| E7 | 0.14 | enumerates ids within a single template | F6 |
| E9 | 0.12 | uses more than one execution channel (User-Agent family) in parallel | F9 |
| E11 | 0.12 | continues activity after 404 responses | F3 |
| E12 | 0.10 | revisits an endpoint after receiving a 2xx | F6 |
| E15 | 0.00 | dictionary-driven enumerator: high 4xx ratio, low 2xx rate, high template count | F13 |

The complete table, with the exact conditions and thresholds, is in
`docs/METHODOLOGY.md` and in `research/engine/evidence.py`. E10 carries a weight of 0.95 but is
excluded from the fusion algebra because it depends on response-side data that a passive
collector does not have.

### 5.4 Fusion and the decision rule

Positive evidence is fused with a noisy-OR model:

```
score(actor) = 1 - Π_i (1 - w_i)
```

over the positive rules that fire. The form is chosen for three properties: it is
monotone in every weight; it is the union bound of independent events, so weights are
directly interpretable as diagnostic strength; and it is trivially computable and
auditable.

Negative rules do not enter the product. E15 instead acts as a **cap**: an actor matching
the dictionary-driven-automation profile is classified as non-agent regardless of how much
positive evidence it accumulates. This is deliberate. An agent running in a low-intensity
mode, or with a narrow scope, degenerates into dictionary enumeration, and at that point the
actor's traffic carries no information that distinguishes it from a human running the same
dictionary - so scoring it as an agent would be wrong.

Three algebraic properties of the decision rule are worth stating, because they constrain
what the detector can and cannot do:

| Property | Value | Consequence |
|---|---|---|
| Largest single-rule weight | 0.34 | Below the default threshold of 0.35, so **no single rule can convict** |
| Minimum convicting rule count | k_min = 2 | At least two independent evidence rules must fire |
| Strongest single family | F3 at 0.40864 | **One family can convict** if all three of its rules fire |

The middle row was initially reported incorrectly as 'a single family cannot convict'. The
correction matters: F3 alone reaches 0.40864, above the threshold, so the F3 family is
load-bearing in a way the others are not - which the ablation in Section 7.5 confirms
empirically.

### 5.5 Signature tiers and the rule-usability screen

Signature candidates are drawn from the audited source and verified line by line: a
candidate is admissible only if the recorded string is the literal value at the recorded
file and line, and only if the request scope is the target (as opposed to a third-party
service, an LLM provider, or the loopback interface).

Surviving candidates are then tiered. A rule is T1 only if it is framework-exclusive, has
target scope, is not a generic client behaviour, is not an attack semantic a human would
also produce, and **matches zero rules and zero actors across both real corpora**. T2
expresses attack semantics without attribution value. T3 is generic tooling or over-broad
and is excluded from deployment.

Static analysis cannot supply the last condition, and it is the condition that removes the
most rules. Six categories of candidate are discarded by a dedicated usability screen before
tiering:

| Category | Example | Disposition |
|---|---|---|
| Source-code templates | `f"/{path[0]}/1/{path[2]}"` | T3 - the emitted request carries the evaluated value, not the template |
| Descriptive text mixed into the literal | a literal prefixed with a non-ASCII descriptive phrase | T3 - cannot match real traffic |
| Placeholder tokens | `https://{target}/graphql` | T3 |
| Example hostnames | `X-Forwarded-Host: attacker.com` | T3 |
| Generic credentials and command templates | `admin:admin`, `nc -e /bin/bash attacker.com` | T2 - a human sends the same thing |
| Identifier lists and prototype-pollution payloads | `com.opensymphony.xwork2.ActionContext / ...` | T2 |

The screen removed 68 rules that were otherwise plausible. Several of them would have been
deployed as strong signals and would have produced no detections at all.

### 5.6 Signature matching semantics

Generation, validation and export share one implementation of the matching semantics. A
literal is escaped, `*` becomes a wildcard that cannot cross whitespace or a path
separator, and the resulting expression is normalised for the target platform (notably,
`\s` is not supported by the Lucene-style query languages and is replaced). Sharing one
implementation is not a stylistic choice: earlier versions of this work shipped deployable
files whose validation semantics differed from the generator's, and the failure was only
caught because the exported files were counted rather than parsed.

---

## 6. Framework Corpus and Audit Procedure

### 6.1 Corpus

The corpus comprises 65 audited codebases - 64 third-party frameworks plus one in-house
implementation - selected to span the designs that actually
exist rather than a single architectural family: prompt-driven agents, orchestrated
tool-calling agents, multi-agent pipelines, and skill-library designs. The audit recorded, for
each framework, the request-sending code paths and the strings they emit.

### 6.2 Audit procedure

Each framework is audited statically. For every candidate string the auditor records the
file and line, the request scope (target, third-party service, LLM provider, loopback),
whether the call site is live or dead, and the attack stage at which it is emitted. Three
classes of string are systematically excluded and reported separately: values appearing only
in test fixtures, documentation and demo data; values with no live call site; and generic
tooling identifiers (curl, wget, python-requests, Go-http-client, ffuf, nuclei, httpx,
sqlmap, browser User-Agents). The last group is reported rather than discarded, because
knowing which frameworks are *only* observable through generic tooling is itself a finding.

### 6.3 Attribution matrix

The matrix in `docs/FRAMEWORK_COVERAGE.md` records, per framework, whether it emits its own
identifying request, whether it is attributable on the target side, how it was validated,
and - where it could not be run - the specific blocker.

The headline numbers:

| Category | Count |
|---|---:|
| Codebases audited (64 third-party frameworks + 1 in-house) | 65 |
| Frameworks with T1 source-level signatures | 41 framework labels |
| **Frameworks validated end-to-end as attributable on the target side** | **10** |
| Frameworks whose target-side traffic is entirely generic tool traffic | 18 (run and inspected) |
| Frameworks that cannot produce HTTP target traffic at all, or could not be executed | remainder |

The gap between 41 and 10 is the single most important number in this paper. Forty-one
frameworks contain a string that could, in principle, identify them - but for most of them
that string never reaches the victim, because the framework's HTTP client is used to talk to
its own tooling or to an LLM provider, not to the target.

---

## 7. Results

### 7.1 Signature validation on real traffic

| Corpus | Requests / transactions | T1 rules matched |
|---|---:|---:|
| Public internet traffic | 9,905,794 requests, 80,987 source addresses | **0** |
| Real WAF attack transactions (30 days) | 142,705 | **0** |

Sixteen rules matched on the public corpus. Every one is T2 or T3: browser-disguise
User-Agents, a bare `Python/3`, a public out-of-band-interaction domain, generic payload
markers. None is deployable for attribution, and none is included in the released T1 set.

Under the combinatorial criterion - one source address matching at least two T1 rules - the
public corpus yields exactly **one** flagged address out of 80,987.

### 7.2 Behavioural detection

| Metric | Value |
|---|---|
| Actors | 15 live AI-agent captures, 12 frameworks |
| Segment recall at threshold 0.35 | **13/15 = 86.7%** |
| Framework recall | **10/12 = 83.3%** |
| Framework-level one-sided 95% lower bound | **0.779** (0.05^(1/12)) |
| Per-actor scores | 0.803 (DSH) down to 0.250 (pentest-ai) |

Clopper-Pearson and Jeffreys intervals over the segment-level proportion are reported in
`docs/RESULTS.md`.

### 7.3 False positives

| Negative set | Actors | False positives | FPR |
|---|---:|---:|---:|
| Real attackers (WAF-derived) | 1,582 | 43 | **2.72%** (95% CI [2.02%, 3.64%]) |
| Scanner actors | 6 | 4 | **66.67%** |

The two numbers differ by more than an order of magnitude because the populations differ in
kind, not degree. The WAF-derived actors are predominantly browser-driven and
interactive; the scanner actors are enumeration tools. Section 8.1 develops this.

### 7.4 Generalisation: leave-one-framework-out

Holding out each framework in turn and re-fitting the decision rule on the rest yields
detection in **9 of 10** folds. The failing fold is the framework with the smallest capture
(62 requests), which is below the volume the behavioural features require - a sampling
limitation rather than a conceptual one.

### 7.5 Family ablation

Removing one feature family at a time and measuring the recall ceiling:

| Removed family | Recall ceiling | Change |
|---|---:|---:|
| none (base) | 0.933 | - |
| **F3** | **0.733** | **-0.200** |
| F6 | 0.867 | -0.067 |
| F4, F5, F7, F9, F10 | 0.933 | 0.000 |

F3 is the load-bearing family, exactly as the algebra predicted: it is the only family
whose three rules can jointly exceed the threshold, and it carries the post-error
behaviour that distinguishes an agent from a brute-force script.

---

## 8. Discussion

### 8.1 The attribution boundary

Three independent lines of evidence show that an AI agent which delegates its work to
general-purpose tooling is not distinguishable from a human using the same tooling.

**Evidence 1 - an agent that calls sqlmap.** One audited framework, run live against the
evaluation target, spent its entire engagement inside a single tool invocation. Every
request the target observed carried `sqlmap/1.10.4`. The agent's own identity - its
orchestration, its planning, its tool selection - left no mark on the target at all.

**Evidence 2 - scanner actors produce systematic false positives.** Six real enumeration
tools were run against the evaluation target in isolated containers and their traffic scored
by the behavioural detector. Four of the six were flagged at the operating threshold, and
raising the threshold did not reduce the count. The reason is structural: the features that
separate an agent from a human are features of *adaptivity* - switching endpoint family
after an error, revisiting an endpoint that returned success, rotating identities - and a
well-written enumeration script exhibits the same behaviours when it is fed a wordlist.

**Evidence 3 - a real agent degenerating into a tool.** A framework with an unusually
distinctive own signature was run in a low-intensity configuration. Its traffic was
characterised by 428 endpoint templates explored in 936 seconds, a 99% 4xx ratio, a 1% 2xx
rate and 442 requests per minute. The behavioural detector scored it 0.250 - below threshold -
and the reverse-evidence rule E15 classified it as a dictionary-driven enumerator. The
framework *is* an AI agent, and the detector is right not to claim otherwise: at that
operating point the traffic carries no information that separates it from a human running
the same dictionary.

These three observations are the same phenomenon seen from three sides, and they bound what
passive HTTP inspection can achieve. When an agent is adaptive - when its next request is
chosen in response to the previous response - the behavioural signal exists and is
measurable. When the agent is running a fixed procedure, the signal is absent and no
threshold can manufacture it.

### 8.2 What a defender can do

**Deploy the T1 signatures for attribution, not for alerting on their own.** Their value is
precise: when one fires, the framework is identified. Their false-positive rate on real
traffic is zero over 10 million requests, and the combinatorial criterion keeps the alert
volume at one address per 81,000.

**Treat them as a complement to, not a replacement for, behavioural detection.** The
signatures answer which framework; the behavioural layer answers whether an agent was
involved. A deployment that expects signatures to answer both will conclude that AI agent
traffic is invisible whenever the agent delegates its work.

**Correlate egress traffic.** An agent must talk to an LLM provider. That traffic is
reliably attributable to an agent in a way that target-side traffic is not, and it is
observable on the same segment. This is the recommendation we make most strongly, and it is
the one control that survives the boundary described in Section 8.1. We do not evaluate it
here.

**Expect the signatures to decay.** Section 9.3 discusses maintenance.

### 8.3 Offensive risk of publishing this work

Publishing signatures lowers the cost of evasion for a framework author who chooses to
change a User-Agent string. Publishing the behavioural thresholds lowers it further, because
the thresholds define exactly which behaviours are scored.

We accept that trade-off, for three reasons. The behavioural signals that matter are
adaptive behaviours - switching family after an error, revisiting after success, rotating
identities - and removing them costs the attacker the effectiveness that makes agentic
attack worth using; a genuinely adaptive agent cannot be made to look like a script without
becoming one. The signature half decays quickly regardless of publication, because
frameworks change their own markers as a matter of course. And the boundary finding in
Section 8.1 is the most useful thing in this paper for defenders, and it cannot be used to
evade anything - it describes what is *not* detectable.

`docs/THREAT_MODEL.md` develops this analysis, including the authors' view on which
signatures should be withdrawn on request.

---

## 9. Limitations

### 9.1 Statistical limitations

The negative actor set contains 1,582 actors. That supports a false-positive rate estimate
of 2.72% with a 95% interval of [2.02%, 3.64%], but it does **not** support a claim of
'below 1%' - the rule-of-three bound at this sample size is 0.19%. Scanner-actor coverage is
smaller still: six actors, 999 requests, dominated by one tool (910 of 999 requests are from
a single enumeration tool), so the 66.67% figure characterises that tool's behaviour rather
than a balanced multi-tool population.

The WAF-derived negative corpus contains no successful (2xx) responses - a WAF records
requests it flags, not the traffic that passes - so features that depend on success
responses are under-tested on that corpus.

The leave-one-framework-out evaluation covers ten frameworks, not sixty-five, because the
other fifty-five were never executed.

### 9.2 Coverage limitations

Signatures reflect the audited revision of each framework and are invalidated by upstream
changes. Frameworks that were never executed contribute source-level signatures whose
target-side behaviour was inferred from code reading rather than observed. The framework
count of 65 is an audit count; the attribution count of 10 is a measurement count, and only
the second is evidence.

### 9.3 Maintenance

A signature set derived from source code decays as frameworks change. The maintenance model
in `CONTRIBUTING.md` asks framework authors to submit or confirm their own signatures, on
the grounds that they know their own markers better than a static audit can. A submission
or retraction request from an upstream maintainer is honoured.

---

## 10. Reproducing the Results

Every number in this paper is asserted by continuous integration against the shipped
artefacts. The dataset, the signature set and the evaluation code are in this repository.

```bash
cd research
pip install -r requirements.txt

# score the published positive and negative captures
python pipeline/score_actor.py --input ../data/positive --out ../out/actor
python pipeline/score_actor.py --input ../data/negative --out ../out/actor-neg

# evaluation
python evaluation/evaluate_detection.py --actors ../out/actor --out ../out/metrics.json
python evaluation/false_positive_eval.py --features ../data/features --out ../out/fp.json
python evaluation/lofo.py --actors ../out/actor --out ../out/lofo.json
python evaluation/family_ablation.py --actors ../out/actor --out ../out/ablation.json
python evaluation/threshold_sweep.py --actors ../out/actor --neg ../data/features --out ../out/sweep.csv

# signature and headline validation (this is what CI runs)
python ci/check_signatures.py --rules ../signatures/rules.json --platform-dir ../signatures
python ci/check_signatures.py --rules ../signatures/agpl/rules-agpl.json --platform-dir ../signatures/agpl
python ci/selftest_rules.py --rules ../signatures/rules.json
python ci/check_headline_numbers.py
```

The reproducibility claim has a precise scope. Re-scoring the published captures reproduces
the recorded score exactly for 10 of the 15 positive captures; for the remaining five the
published file is the complete pseudonymised capture, whereas the recorded score was
computed on the agent-labelled subset of the original capture, so a full re-score is not
directly comparable. The numbers quoted in this paper are read from
`data/aggregate/framework_detection.json`; the pipeline demonstrates that the computation
itself is reproducible.

The dataset card (`data/DATASET_CARD.md`) records provenance, collection procedure,
licensing, intended use and the limitations of each corpus, including the pseudonymisation
scheme applied to the real-attacker actor set.

---

## 11. Conclusion

We audited 65 AI-pentest codebases (64 third-party frameworks plus one in-house implementation), extracted 610 traffic signatures of which 272 are
strong enough to deploy and match zero rules across 10 million real requests and 142,705
real attack transactions, and built an actor-level behavioural detector that reaches 86.7%
segment recall at a 2.72% false-positive rate on real attackers.

The more useful result is the boundary. Only 10 of the 65 audited codebases are attributable on the
target side; for the rest, the agent's identity does not reach the victim. Where the agent
delegates to general tooling, passive HTTP inspection cannot separate it from a human, and
the evidence for that is threefold and consistent. A defender who expects signatures alone
to answer the question will conclude that agentic traffic is invisible; the accurate
statement is narrower and more actionable: agentic traffic is visible when the agent is
adaptive, and invisible when it is not - and the reliable signal in both cases is the
agent's outbound traffic to an LLM gateway, not its inbound traffic to the target.

---

## References

The audited frameworks, with per-framework provenance for every signature, are listed in
`NOTICE` and in the `framework` and `source` fields of `signatures/rules.json`. Each
signature records the upstream repository, file path and line number from which it was
extracted.

*This document is the paper associated with the `ai-agent-attack-signatures` repository. All
numbers are asserted by CI against the shipped artefacts.*
