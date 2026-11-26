# Threat model

This document analyses the defensive value and the offensive risk of publishing this material,
states what an adversary gains and what remains hard, and describes the maintenance model.

It is written to be read before deploying anything from this repository.

---

## 1. What an adversary gains from reading this

### 1.1 The signature literals

The tier-1 rules are, by construction, exact strings that appear in the framework's own HTTP
requests: user agents, header names, path fragments, payload templates. Publishing them makes
them public, and a public literal is a literal that can be changed. The 272 tier-1 rules cover
41 framework labels across 6 observable fields:

| Field | Rules | What an adversary learns |
|---|---:|---|
| Request body | 150 | The exact payload templates the framework's skills inject |
| Request path | 37 | The path fragments and canary paths the framework probes |
| HTTP request header | 36 | The attribution headers the framework injects |
| User-Agent | 35 | The framework's user agent string |
| Other (TLS, proxy, credential) | 12 | TLS client characteristics, proxy markers, credential formats |
| OAST domain | 2 | The out-of-band interaction domains |

The mitigation is obvious and available to an adversary: change one string. The cost to them is
one line of source; the cost to a defender is a signature that has to be re-audited. This is
not a hypothetical risk - it is measurable in this project's own history.

**The measured decay.** When the corpus grew from 38 to 65 frameworks in the study's
expansion round, 7 of the newly added rules matched real public traffic and had to be demoted.
The named examples are generic Chrome-masquerade user agents, `Python/3`, the bare token
`cyber`, a public Googlebot user agent, a `True-Client-IP` private-address forgery, and public
OAST service domains. None of these is distinguishable from ordinary traffic by reading the
source. **Only a scan against a large real-traffic corpus exposes them.** Publishing a rule set
that has not been through that scan would have shipped rules that fire on the open internet.
The hit counts these rules accumulated on the shipped 9,905,794-request corpus are in
`RESULTS.md` section 6.2; the six Chrome-masquerade and `Python/3` rules alone account for
4,456,780 and 8,853 requests respectively.

### 1.2 The rule conditions and their thresholds

`METHODOLOGY.md` section 3 publishes the exact conditions of all 15 evidence rules and their
thresholds. An adversary who wants to avoid the behavioural detector can now compute, offline,
the minimum behaviour set that still clears 0.35 - for instance, that E5, E6 and E11 together
reach 0.4086 from the feedback-adaptivity family alone, so the error-adaptation evidence can
be suppressed by not changing route after errors. The conditions are also the only way to
audit the detector, so publishing them is not optional for a method that anyone else is meant
to verify.

### 1.3 The false-positive structure

The discrimination table in `RESULTS.md` section 8 says which rules fire on ordinary
attackers and which do not:

* E3 (identity rotation), E4 (machine naming) and E9 (multi-channel orchestration) fire on
  **0%** of real attackers.
* E7 (enumeration breadth) fires on 3.0%, E1 on 2.2%.
* E5 fires on 16.4%, E6 on 41.8%, E11 on 24.4%, E2 on 15.7%, E14 on 22.2%.

An adversary who reads this learns exactly which behaviours to drop. Dropping identity
rotation, machine naming and multi-channel orchestration removes the three most discriminative
features without measurably increasing the false-positive rate on humans.

### 1.4 What the counter-analysis costs in aggregate

Publishing the rule set plus the method is equivalent to publishing a bypass recipe. The
realistic worst case is an agent that (a) sets a generic user agent, (b) uses one identity,
(c) stays in one tool channel, and (d) changes route rarely. Such an agent would fall below
the F3 family conviction threshold and, depending on volume, may score below 0.35.

**This is not a hypothetical worst case; it is close to what the light-weight agents in the
corpus already do.** hackingBuddyGPT scores 0.2800 and pentest-ai scores 0.2500 without any
adversary in the loop. The published threshold is not far above the behaviour that already
exists in the wild.

---

## 2. What remains hard

### 2.1 The response-adaptive loop cannot be removed without removing the attack

The behavioural layer does not measure a fingerprint. It measures evidence that the actor
**read the previous response and changed its next request accordingly**. Concretely: errors
that lead to a route change, endpoint families that get abandoned after repeated failure,
requests that revisit an endpoint after a success, identities that rotate when one is refused.

An adversary can suppress individual *behaviours* - stop rotating identities, stop switching
tools. What cannot be suppressed while remaining effective is the **loop itself**:

* An agent that never changes route after an error keeps attacking a dead endpoint, and
  succeeds less often. That is not a cosmetic loss; it is the difference between a working and
  a non-working attack.
* An agent that never revisits an endpoint after a success cannot confirm its own findings, so
  it cannot report verified results.
* An agent that uses one channel cannot both explore broadly and exploit deeply in the same
  turn, because the two require different tools.

So the adversary's optimisation problem is not "avoid the signatures". It is "become less
effective while remaining less detectable". **The incentive structure is aligned against the
adversary here**, and this is the property the whole method rests on. The same is true of the
outbound signal in section 3: an agent that does not call a model is not an agent.

### 2.2 The negative-evidence rules cannot be evaded by adding volume

E14 and E15 cap the score at 0.25 rather than adding to it. The deeper point is that they
detect a *shape* (dictionary enumeration) rather than a *literal*. An adversary cannot evade
E15 by changing user agents or payloads; they can only evade it by not enumerating
systematically - which is by definition no longer dictionary-driven enumeration.

### 2.3 The egress signal is not a fingerprint either

The outbound-to-LLM-gateway signal cannot be evaded by changing any request field, because it
is not a request field. It requires the adversary to stop using a model, at which point the
"AI agent" designation no longer applies.

### 2.4 What is genuinely exposed

| Exposed | How hard to mitigate |
|---|---|
| Tier-1 literals | Easy to change; requires re-audit by the defender |
| Behavioural rule thresholds | Moderately hard; suppressing the behaviours costs attack effectiveness |
| The false-positive profile | Moderately hard; the discriminative rules are the ones tied to the agent loop |
| The egress correlation idea | Hard; avoiding it means not using a model |
| The negative-evidence shape rules | Hard; avoiding them means not enumerating systematically |

---

## 3. What actually works in deployment

The recommendation from `LIMITATIONS.md` section 3, restated as a deployment form:

> **Passive HTTP behaviour detection plus attack-source egress correlation.**

Neither layer alone covers the population:

| Layer | Covers | Fails on |
|---|---|---|
| Tier-1 signatures | Agents whose own client is visible: 10 of the 64 audited frameworks | The other 54; and any agent that changes its user agent |
| Behavioural detection | Agents that issue requests themselves: 13 of 15 captures at 86.7% recall, 2.72% FPR on real attackers | Agents that delegate to tooling: 66.67% FPR on the scanner population |
| Egress correlation | Every agent, including ones that delegate | Requires egress logs, which a purely passive deployment does not have |

### 3.1 Operational guidance

**Deploy tier 1 only.** Tier 2 is attack evidence - it proves a tool is attacking but cannot
distinguish an AI agent from a script, and deploying it alone means alerting on every scanner.
Tier 3 is withdrawn and must not be deployed against internet-facing assets. Every platform
rule file carries a `tier` field, so the split is a filter:

```bash
grep -i 'tier.*T1' signatures/ioc_rules_es.kql | head
```

**Alert on actors, not on requests.** The decision unit is one source address within one time
window. On the 9,905,794-request public traffic scan, exactly 1 of 80,987 source addresses
matched two or more rules, so the alert volume is bounded by the actor population, not by the
request rate.

**Replay your own traffic before going to production.** Tier-1 rules matched zero of
9,905,794 public internet requests and zero of 142,705 real WAF attack transactions in this
study. Your environment differs. The check is cheap and the failure mode is silent.

**Tune the threshold, but know what tuning buys.** The measured trade-off (RESULTS.md section
5): moving from 0.35 to 0.50 reduces the false-positive rate on real attackers from 2.72% to
0.19% and costs two actor captures and two frameworks. Moving to 0.60 eliminates the scanner
false positives entirely and costs four frameworks. **No threshold fixes the tool-driven
population** - see section 2 of `LIMITATIONS.md`.

**Pair with egress correlation.** If egress logs are available at all, the LLM-gateway
correlation is the signal that covers the delegated-agent case, and it is the one that no
request-level evasion can defeat.

**Do not run the behavioural layer against a population that is mostly scanners.** At 2.72%
false positives on real attackers and 66.67% on tool-driven traffic, the operational question
is what proportion of the traffic in the deployment is agent-driven. On a research network
with AI agents everywhere the trade-off looks different from on a general internet-facing
estate.

### 3.2 What not to do

* **Do not treat a tier-1 hit as proof that an AI agent was involved.** A tier-1 hit proves
  that a specific framework's client sent the request. It does not prove an agent was
  *deciding* - a script could replay the same client. This is the distinction between
  attribution and detection, and it is the most common misreading of a catalogue like this one.
* **Do not deploy tier-2 rules as standalone alerts.** They were measured at 16.4% to 41.8%
  negative coverage on real attackers.
* **Do not assume a framework with a tier-1 rule is detectable.** Only 10 of the 64 audited
  frameworks were confirmed end to end; 34 have no framework-owned target-side signal at all.
  See `FRAMEWORK_COVERAGE.md`.

---

## 4. Maintenance model

A signature set rots fast, and the study's own evidence quantifies the rate. The maintenance
model below is designed around that.

### 4.1 The refresh cycle

| Step | Cadence | What it produces |
|---|---|---|
| Re-download every audited repository and re-read the source | Quarterly | An updated indicator inventory per framework |
| Re-scan the updated rule set against a large public traffic corpus and a WAF attack corpus | With every refresh | The tier-1 zero-hit invariant, re-verified |
| Re-score the published capture corpus | With every refresh | Whether the detector still reproduces the published scores |
| Retire rules that no longer match | Continuous | A smaller, honest rule set |

The invariant that must hold at every refresh is: **tier-1 rules match zero on both real
corpora**. It is checked automatically by `research/ci/check_headline_numbers.py` and
`research/ci/selftest_rules.py`.

### 4.2 The two-stage maintenance loop

The study's own findings argue for a specific loop, and it is the loop the upstream work
already ran:

```
static source audit  ->  real run and capture  ->  measured feedback  ->  deliver
                            ^                                    |
                            +--------- backfill on the next audit --+
```

**Why the static stage alone is not enough.** The audit of AutoPT's own user agent classified
it as "not observable on the target side" and demoted it to tier 3. A later real run found
`AutoPT/1.0` on the target side twice. A static rule that says "scope unknown, therefore
withdraw" silently destroys real fingerprints.

**Why the measured stage alone is not enough either.** During the same measurement, the
highest-volume user agents observed were all generic tools - sqlmap 11,711 times, ffuf 11,146
times, gobuster 9,501 times, Nmap 2,225 times, Nikto 966 times, curl 1,067 times,
python-requests 946 times. None of them belongs in a framework fingerprint catalogue, and their
exclusion is confirmed by measurement rather than by assumption.

**The backfill.** Two rules were added to the catalogue purely because a measurement showed
them: the in-house frameworks' own user agents, observed 61 times and 3 times respectively,
and AutoPT's own user agent, observed twice. All three are now tier 1.

### 4.3 The request to framework authors

**This repository would rather have a signature from you than a signature about you.**

The study audits frameworks by downloading repositories and reading source. That is slow, it
is incomplete, and it is wrong whenever a maintainer has changed something the audit has not
seen. A framework maintainer knows their own markers better than an auditor does.

Three ways to contribute, in increasing order of usefulness:

1. **Confirm a signature.** If a rule in this catalogue matches your framework's traffic, say
   so. A confirmation is evidence, and it is what turns "one auditor read the source once" into
   "the author verified it".
2. **Submit a signature.** If your framework leaves a target-side marker that is not in the
   catalogue, contribute it. The bar is the same as for every other rule: it must be a literal
   that appears in a real request, it must not be a generic header name, a public tool user
   agent or a documentation placeholder, and it must match zero on real public traffic and zero
   on real attack traffic.
3. **Retire a signature.** If a rule in this catalogue no longer matches your framework,
   tell us and we will retire it. **A signature that fires on nothing is worse than no
   signature**, because it manufactures confidence.

**We will also honour a removal request.** If a framework maintainer asks for a signature to be
withdrawn, we will withdraw it. The catalogue's value is that its entries are true, and a
maintainer's word about their own framework is better evidence than our reading of it.

**What we cannot accept.** A signature that is a documentation placeholder, a source-code
template, a public tool identity, or a weak credential. Those are not framework fingerprints,
and they will fire on ordinary traffic. The screen is in `METHODOLOGY.md` section 7.1 and the
gates are in section 7.2.

### 4.4 Deprecation policy

* A rule that stops matching a real run of its own framework is **retired**, not left in place.
* A rule that starts matching real public traffic is **demoted**, not defended.
* A framework that is withdrawn upstream keeps its audit record and its capture, marked as
  withdrawn, so that the corpus remains auditable.

---

## 5. Balance of the disclosure decision

| Consideration | Assessment |
|---|---|
| Risk of publishing the literals | Real and measurable: 7 of 65 rules in the last expansion had to be demoted after a real-traffic scan. The maintenance burden falls on defenders. |
| Risk of publishing the behavioural thresholds | Real but bounded: the behaviours that are discriminative are the ones that make the attack work. |
| Value of publishing the negative finding | High and not exploitable in the same way: "most AI agents are indistinguishable from a human running the same tool" is a statement about an absent attribution surface. It redirects effort away from chasing user agents that will never be there. |
| Cost of not publishing | The method stays with one team. Deployers re-derive it worse, or not at all. |
| Cost of the alternatives | Neither the signatures nor the method can be kept secret in any meaningful sense once used against production traffic. |

**The decision.** Publish. The defensive value of a method that only its authors can run is
limited to its authors, and the study's most important output - the measurement that
attribution stops working for 34 of 64 frameworks - cannot be exploited the way a rule list
can. The maintenance model in section 4 is the mitigation for the literal-exposure risk, and
the request in section 4.3 is the mitigation for the coverage risk: the maintainers of the
frameworks know their own markers better than any auditor does, and they are better placed to
keep them correct.

**Read this document before deploying.** The signatures are safe to deploy in the sense that
they match zero on 10 million records of real traffic. They are not safe in the sense that they
will stay correct without maintenance, and the behavioural layer is not safe in the sense that
it will separate an AI agent from a human running the same tool.

---

## 6. Where to look next

| Question | Document |
|---|---|
| How is the detector built and what are its constants? | `METHODOLOGY.md` |
| How was the data collected and evaluated? | `EXPERIMENTS.md` |
| What are the numbers? | `RESULTS.md` |
| Which frameworks are attributable and which are not? | `FRAMEWORK_COVERAGE.md` |
| What does this not establish? | `LIMITATIONS.md` |
