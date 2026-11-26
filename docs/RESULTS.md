# Results

All numbers in this document are read from the shipped artefacts and were re-derived with the
repository's own evaluation scripts. The re-derivation command is given with every table; the
CI script `research/ci/check_headline_numbers.py` re-computes the headline figures from the
same artefacts and fails the build if the documentation disagrees with them.

Decision threshold used throughout: **0.35**. Source of truth for the per-actor scores:
`data/aggregate/framework_detection.json` (15 AI-agent actor captures, 12 frameworks).

---

## 1. Behavioural detection, per actor capture

Source: `data/aggregate/framework_detection.json`, `data/positive/_index.json`.
Positive corpus: 15 actor captures, 12 frameworks, 211,547 published request records.

| Actor capture | Framework | Requests scored | Duration (s) | AI score | Fired rules | Detected at 0.35 |
|---|---|---:|---:|---:|---|---|
| DSH-1 | DSH | 1,519 | 1,703 | 0.8030 | E1, E3, E4, E6, E7, E9, E11, E12 | yes |
| strix-1 | strix | 31,024 | 1,761 | 0.7980 | E1, E3, E5, E6, E7, E9, E11, E12 | yes |
| DSH-2 | DSH | 1,273 | 3,029 | 0.7853 | E1, E2, E3, E6, E7, E9, E11, E12 | yes |
| PentAGI-2 | PentAGI | 384 | 7,563 | 0.7740 | E1, E2, E5, E6, E7, E9, E11, E12 | yes |
| DSH-3 | DSH | 838 | 3,128 | 0.7475 | E1, E3, E6, E7, E9, E11, E12 | yes |
| PentAGI-1 | PentAGI | 1,512 | 7,562 | 0.7342 | E1, E5, E6, E7, E9, E11, E12 | yes |
| CyberStrikeAI-1 | CyberStrikeAI | 85 | 813 | 0.6576 | E2, E5, E6, E7, E9, E11, E12 | yes |
| AntiFox-1 | AntiFox | 2,713 | 852 | 0.6174 | E3, E6, E7, E9, E11, E12 | yes |
| ARTEX-1 | ARTEX | 2,006 | 881 | 0.6174 | E3, E6, E7, E9, E11, E12 | yes |
| xalgorix-1 | xalgorix | 47 | 86 | 0.5404 | E3, E5, E6, E12 | yes |
| PentesterFlow-1 | PentesterFlow | 767 | 827 | 0.5059 | E3, E6, E7, E12 | yes |
| raptor-1 | raptor | 1,252 | 271 | 0.4279 | E6, E7, E11, E12 | yes |
| AutoPT-1 | AutoPT | 4,530 | 94 | 0.4146 | E6, E9, E11, E12 | yes |
| hackingBuddyGPT-1 | hackingBuddyGPT | 62 | 268 | 0.2800 | E5, E12 | **no** |
| pentest-ai-1 | pentest-ai | 6,888 | 936 | 0.2500 | E1, E5, E6, E7, E11, E12, E15 | **no** |

Per-framework roll-up (source: `data/aggregate/framework_detection_summary.csv`):

| Framework | Captures | Detected | Max score | Min score | Mean score | Requests |
|---|---:|---:|---:|---:|---:|---:|
| DSH | 3 | 3 | 0.8030 | 0.7475 | 0.7786 | 3,630 |
| PentAGI | 2 | 2 | 0.7740 | 0.7342 | 0.7541 | 1,896 |
| ARTEX | 1 | 1 | 0.6174 | 0.6174 | 0.6174 | 2,006 |
| AntiFox | 1 | 1 | 0.6174 | 0.6174 | 0.6174 | 2,713 |
| CyberStrikeAI | 1 | 1 | 0.6576 | 0.6576 | 0.6576 | 85 |
| strix | 1 | 1 | 0.7980 | 0.7980 | 0.7980 | 31,024 |
| xalgorix | 1 | 1 | 0.5404 | 0.5404 | 0.5404 | 47 |
| PentesterFlow | 1 | 1 | 0.5059 | 0.5059 | 0.5059 | 767 |
| raptor | 1 | 1 | 0.4279 | 0.4279 | 0.4279 | 1,252 |
| AutoPT | 1 | 1 | 0.4146 | 0.4146 | 0.4146 | 4,530 |
| hackingBuddyGPT | 1 | 0 | 0.2800 | 0.2800 | 0.2800 | 62 |
| pentest-ai | 1 | 0 | 0.2500 | 0.2500 | 0.2500 | 6,888 |

### The two misses, and why they are informative

* **hackingBuddyGPT (0.2800)** fires only E5 and E12. It is a light-weight agent that issues
  single requests through `python-requests/2.34.2`: 62 requests over 268 s, one user-agent
  family, mostly 2xx responses. It therefore produces no scale evidence (E1), no multi-channel
  evidence (E9), no error-tolerance evidence (E11) and no enumeration breadth (E7). The
  tool-fingerprint axis is 0.175. This is a genuine blind spot of the behavioural layer, not a
  scoring artefact.
* **pentest-ai (0.2500)** fires six forward rules including E1, but is **capped by the reverse
  evidence rule E15**: in 936 s it enumerated 428 endpoint templates at 99% 404 responses, 1%
  2xx responses and 442 requests per minute. E15 classifies that as dictionary-driven
  enumeration, not agent behaviour, and caps the score at 0.25. The cause is the framework's own
  configuration (`--scope web --intensity safe`): at low intensity it degenerates into
  dictionary enumeration. Note that the IOC layer *does* attribute this traffic: its user agent
  `pentest-ai/1.6.2 (compatible; rv:<12hex>; +https://pentestai.xyz)` is present on 100% of the
  6,888 requests.

---

## 2. Recall, with exact intervals

Source: `data/aggregate/framework_detection.json` + `data/features/actor_features.jsonl`.
Reproduce with:

```bash
python -m research.evaluation.evaluate_detection
```

| Level | Detected | Total | Recall | Clopper-Pearson 95% | Jeffreys 95% |
|---|---:|---:|---:|---|---|
| Segment (actor capture) | 13 | 15 | 86.67% | [0.5954, 0.9834] | [0.6366, 0.9712] |
| Framework | 10 | 12 | 83.33% | [0.5159, 0.9791] | [0.5638, 0.9637] |

**Framework-level generalisation bound.** For the claim "all *k* frameworks are detected", the
one-sided 95% lower confidence bound is `0.05^(1/k)`. With **k = 12** validated frameworks:

> **0.05^(1/12) = 0.7791**

This is the strength of the generalisation claim and it is the figure quoted in the README.
The value 0.741 corresponds to k = 10 and appears only inside the leave-one-framework-out
evaluation, where the held-out corpus has 10 folds; it is not the bound for the 12-framework
result set.

The arithmetic is the point: adding more captures of an already-seen framework does not move
the bound, adding a *new framework* does. The bound as a function of the framework count:

| Frameworks *k* | 4 | 5 | 8 | 10 | 12 | 15 | 20 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0.05^(1/*k*) | 0.473 | 0.549 | 0.688 | 0.741 | **0.779** | 0.819 | 0.861 |

---

## 3. Leave-one-framework-out (LOFO)

Source: `data/aggregate/lofo_framework.json` (archived, 10 folds, 56 negative actors) and the
recomputation over the current corpus. Reproduce with:

```bash
python -m research.evaluation.lofo
```

Procedure: hold one framework out completely, calibrate the decision threshold on the remaining
frameworks only (the lowest score that still keeps the remaining frameworks at full recall), then
apply that threshold to the held-out framework.

### 3.1 Archived folds (as shipped)

| Held-out framework | Test actors | Calibrated tau | True positives | Recall | False positives | FPR | Wilson 95% upper |
|---|---:|---:|---:|---:|---:|---:|---:|
| ARTEX | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| AntiFox | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| AutoPT | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| CyberStrikeAI | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| DSH | 3 | 0.2800 | 3 | 1.000 | 0 | 0.000 | 0.0642 |
| PentAGI | 2 | 0.2800 | 2 | 1.000 | 0 | 0.000 | 0.0642 |
| PentesterFlow | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| hackingBuddyGPT | 1 | 0.4146 | 0 | 0.000 | 0 | 0.000 | 0.0642 |
| strix | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |
| xalgorix | 1 | 0.2800 | 1 | 1.000 | 0 | 0.000 | 0.0642 |

**9 of 10 folds detected = 90.0%**, false positives 0 in every fold. The single failure is
hackingBuddyGPT: when it is held out, the calibration threshold rises to 0.4146 (the lowest
remaining framework score) and its 0.2800 no longer clears it.

### 3.2 Recomputation over the current 12-framework corpus

The archived folds predate the two most recent frameworks. Re-running the same procedure over
the shipped 15 captures and 1,582 negative actors gives **11 of 12 folds detected**, with
pentest-ai as the only failure (its score is capped at 0.2500 by E15, and the calibration
threshold for that fold is 0.2800). Both figures are stated here because they measure different
corpora; neither is a subset of the other.

---

## 4. Feature-family ablation: exact recall ceilings

Source: `data/aggregate/feature_family_ablation.json` and
`data/aggregate/framework_detection.json`. Reproduce with:

```bash
python -m research.evaluation.family_ablation
```

The ceiling is **exact, not an estimate**. For each actor, the family weight is removed from the
noisy-OR product and the actor is re-tested against the threshold. The number reported is the
fraction of actors still detected.

| Family removed | Ceiling | Detected / 15 | Effect |
|---|---:|---:|---|
| *(none — base)* | 0.9333 | 14 / 15 | reference |
| F10 (machine naming) | 0.9333 | 14 / 15 | lossless |
| F3 (feedback adaptivity) | **0.7333** | **11 / 15** | **lossy** |
| F4 (rhythm) | 0.9333 | 14 / 15 | lossless |
| F5 (exploration) | 0.9333 | 14 / 15 | lossless |
| F6 (repetition / verification) | **0.8667** | **13 / 15** | **lossy** |
| F7 (identity lineage) | 0.9333 | 14 / 15 | lossless |
| F9 (tool fingerprint) | 0.9333 | 14 / 15 | lossless |

**F3 is the critical family.** If the deployment's logs cannot supply feedback-adaptivity
features, the recall ceiling drops to 73.3%. F6 costs one actor.

Note that the base figure of 14/15 is the *ablation base*, computed without the reverse-evidence
veto; the end-to-end detection result of 13/15 differs by exactly the pentest-ai actor, which the
E15 veto caps at 0.25.

---

## 5. False positives: threshold trade-off, split by attacker type

Source: `data/aggregate/threshold_fpr_tradeoff.json` and
`data/features/actor_features.jsonl`.
Reproduce with:

```bash
python -m research.evaluation.false_positive_eval
python -m research.evaluation.threshold_sweep
```

The negative population is **1,582 real internet attacker actors** derived from a 30-day WAF
audit log, split by the user-agent blob of each actor:

* **human-style attackers** — actor class `browser`, 1,378 actors
* **tool-driven attackers** — actor class `tool`, 204 actors

| Threshold | Human-style (browser) FP / n | FPR | Wilson 95% | Tool-driven (tool) FP / n | FPR | Wilson 95% | All attackers FP / n | FPR | Wilson 95% |
|---:|---|---:|---|---:|---:|---|---:|---:|---|
| 0.30 | 57 / 1,378 | 4.136% | [3.21%, 5.32%] | 10 / 204 | 4.902% | [2.68%, 8.79%] | 67 / 1,582 | 4.235% | [3.35%, 5.34%] |
| **0.35** | **35 / 1,378** | **2.540%** | **[1.83%, 3.51%]** | **8 / 204** | **3.922%** | **[2.00%, 7.55%]** | **43 / 1,582** | **2.718%** | **[2.02%, 3.64%]** |
| 0.40 | 28 / 1,378 | 2.032% | [1.41%, 2.92%] | 6 / 204 | 2.941% | [1.35%, 6.27%] | 34 / 1,582 | 2.149% | [1.54%, 2.99%] |
| 0.45 | 14 / 1,378 | 1.016% | [0.61%, 1.70%] | 3 / 204 | 1.471% | [0.50%, 4.23%] | 17 / 1,582 | 1.075% | [0.67%, 1.71%] |
| 0.50 | 2 / 1,378 | 0.145% | [0.04%, 0.53%] | 1 / 204 | 0.490% | [0.09%, 2.72%] | 3 / 1,582 | 0.190% | [0.06%, 0.56%] |
| 0.55 | 1 / 1,378 | 0.073% | [0.01%, 0.41%] | 1 / 204 | 0.490% | [0.09%, 2.72%] | 2 / 1,582 | 0.126% | [0.03%, 0.46%] |

At the shipped threshold of 0.35 the false-positive rate on real internet attackers is
**2.718% (95% CI [2.02%, 3.64%])**, and it is lower for human-style attackers than for
tool-driven ones (2.540% vs 3.922%).

**Sample-size caveat.** With 1,582 independent attacker actors, a point estimate of 2.718% has a
95% Wilson interval roughly 2.02%–3.64%. The rule-of-three bound (3/n) applies only to a zero
count; here the count is non-zero, so the Wilson interval is the honest statement. To be able to
claim FPR < 1% from a zero count, 300 independent actors are needed; for FPR < 0.1%, 3,000.

### 5.1 Raising the threshold does not fix the scanner population

The scanner hard negatives are the decisive case. Source:
`data/negative/_index.json` and `data/aggregate/threshold_fpr_tradeoff.json`.

| Threshold | Segment recall | Framework recall | FPR, all negatives | Wilson 95% | FPR, real attackers | **FPR, scanner-type actors** |
|---:|---:|---:|---:|---|---:|---:|
| 0.30 | 0.923 | 9/10 | 4.47% | [3.56%, 5.60%] | 4.24% | **66.67%** |
| **0.35** | 0.923 | 9/10 | 2.96% | [2.23%, 3.91%] | 2.72% | **66.67%** |
| 0.40 | 0.923 | 9/10 | 2.39% | [1.75%, 3.27%] | 2.15% | **66.67%** |
| 0.50 | 0.846 | 8/10 | 0.44% | [0.21%, 0.91%] | 0.19% | **66.67%** |
| 0.55 | 0.692 | 6/10 | 0.31% | [0.13%, 0.73%] | 0.13% | **50.00%** |
| 0.60 | 0.692 | 6/10 | 0.13% | [0.03%, 0.46%] | 0.13% | **0.00%** |

The scanner false-positive rate is **flat at 66.67% from tau 0.30 through tau 0.50**. It only
reaches zero at tau 0.60, at a cost of 6/10 framework recall instead of 9/10. The reason is
structural: the scanner actors trigger the same forward rules as the AI agents (E5, E6, E7, E9,
E11, E12), and raising the threshold removes them and the AI agents together.

The six released scanner actors, individually:

| Capture | Source address | Actor class | Records | Dominant tool | AI score | Flagged at 0.35 | E12 fired |
|---|---|---|---:|---|---:|---|---|
| scanner-01 | 127.0.0.1 | tool | 32 | curl | 0.1000 | no | yes |
| scanner-02 | 172.34.0.10 | tool | 205 | ffuf | 0.5972 | **yes** | yes |
| scanner-03 | 172.34.0.11 | tool | 144 | ffuf | 0.5972 | **yes** | yes |
| scanner-04 | 172.34.0.12 | tool | 405 | ffuf | 0.2500 | no | yes |
| scanner-05 | 172.34.0.13 | tool | 144 | ffuf | 0.5972 | **yes** | yes |
| scanner-06 | 172.34.0.15 | browser | 69 | ffuf | 0.5423 | **yes** | yes |

E12 fires on all six. The four flagged actors fire E5, E6, E7, E9, E11 and E12 - the same
forward rules as the AI agents do. The two unflagged actors are the one whose request count was
below the actor minimum (0.1000, E12 only) and the one whose E15 reverse-evidence rule fired
(0.2500, capped).

**What the 66.67% figure characterises.** The released scanner negative set is
**ffuf-dominated**: of the 999 published records, 910 carry `Fuzz Faster U Fool v2.1.0-dev`.
The remaining 89 are curl (35), python-requests (13), masscan (6), Nikto (6), browser-masquerade
user agents (27), Go-http-client (2) and wget (2). No gobuster, nuclei, dirb or nmap record
survives into the released set; in the full 12,666-record source capture sqlmap contributes a
single request. So **66.67% measures the false-positive behaviour of ffuf-style enumeration
against this detector, not of a balanced multi-tool scanner population.** A different enumeration
tool could score differently. The released set is small (6 actors), so the Wilson interval on
4/6 is wide: [30.0%, 90.3%].

---

## 6. Signature validation on two independent real datasets

Source: `data/aggregate/rule_validation_counts.json` and
`data/aggregate/rule_validation_counts.csv`.

### 6.1 The two datasets

| Dataset | Records | Distinct source addresses | Distinct user agents | T1 rules matched |
|---|---:|---:|---:|---:|
| Public internet background traffic (`burpheart/Internet-background-noise`) | 9,905,794 | 80,987 | 80,764 | **0** |
| Real WAF attack transactions (ModSecurity OWASP CRS, 30 days) | 142,705 | not measured | 139,598 carried a user agent | **0** |

Of the 142,705 WAF transactions, 139,598 carried a user agent and **0 carried a request body** —
the audit log format does not record bodies, so the 150 body-field T1 rules could not be
exercised against it. That is a limitation of the validation data, not evidence about the rules.

### 6.2 Rules that did match: 16, all tier 2 or tier 3, none tier 1

| Rule | Tier | Framework label | Indicator | Requests matched | Source addresses |
|---|---|---|---|---:|---:|
| IOC-203 | T3 | deadend-cli | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` | 4,456,780 | 135 |
| IOC-401 | T3 | pentestagent | (same truncated Chrome UA) | 4,456,780 | 135 |
| IOC-595 | T3 | Zen-Ai-Pentest | (same truncated Chrome UA) | 4,456,780 | 135 |
| IOC-596 | T3 | Zen-Ai-Pentest | (same truncated Chrome UA) | 4,456,780 | 135 |
| IOC-243 | T3 | Decepticon | `...Chrome/120.0.0.0 Safari/537.36` | 4,439,847 | 133 |
| IOC-440 | T3 | Pojun | `...Chrome/131.0.0.0 Safari/537.36` | 4,439,847 | 133 |
| IOC-244 | T3 | Decepticon | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` | 110,808 | 61 |
| IOC-045 | T3 | airecon | `Python/3` | 8,853 | 8 |
| IOC-317 | T3 | LuaN1aoAgent | (command-template rule) | 8,156 | 6 |
| IOC-175 | T3 | CyberStrikeAI | `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` | 1,101 | 1 |
| IOC-132 | T3 | cyber-harness | `cyber` | 170 | 4 |
| IOC-499 | T2 | sapper-v2 | `package.json` | 40 | 28 |
| IOC-180 | T2 | CyberStrikeAI | `metadata.google.internal / 100.100.100.200 / 169.254.169.254/latest/meta-data/iam/` | 22 | 1 |
| IOC-398 | T2 | Pentest-Swarm-AI | `http://169.254.169.254/latest/meta-data` | 22 | 1 |
| IOC-465 | T2 | raptor | `actuator/heapdump` | 8 | 3 |
| IOC-245 | T3 | Decepticon | `...Chrome/124.0 Safari/537.36` | 4 | 1 |

**T1 hit count on both datasets is zero.** Every rule that fired is a generic browser or
command-line user agent (tier 3) or a generic attack payload (tier 2) — none is a framework
fingerprint.

### 6.3 Combinatorial criterion: source addresses matching two or more rules

On the 9,905,794-request public traffic scan:

| Rules matched by one source address | Number of source addresses |
|---:|---:|
| exactly 1 | 31 |
| exactly 2 | 1 |
| 3 or more | 0 |

**Exactly 1 of 80,987 source addresses (0.0012%) matched two or more rules.** Because tier-1
rules matched nothing at all, that single address matched two tier-2/tier-3 generic rules. This
is the number that makes an "alert on actors that match >= 2 rules" criterion operational: the
alert volume on real internet traffic is 1 address out of 80,987.

---

## 7. Rule-set composition

Source: `signatures/rules.json` + `signatures/agpl/rules-agpl.json`, summarised in
`data/aggregate/rule_validation_counts.json`.

| Property | Value |
|---|---:|
| Total rules | 610 |
| Tier 1 (framework-exclusive, alertable alone) | 272 |
| Tier 2 (attack evidence, needs corroboration) | 126 |
| Tier 3 (withdrawn: generic tooling / generic headers / dead literals) | 212 |
| MIT-licensed subset | 444 (T1 194 / T2 97 / T3 153) |
| Copyleft-derived subset | 166 (T1 78) |
| Indicator class A rules | 544 |
| Rules with `scope = target` | 610 |
| Distinct framework labels referenced | 44 |

Tier-1 field distribution:

| Field | Rules |
|---|---:|
| Request body | 150 |
| Request path | 37 |
| HTTP request header | 36 |
| User-Agent | 35 |
| Other (TLS, proxy, credential) | 12 |
| OAST domain | 2 |
| **Total** | **272** |

**The rule set references 44 distinct framework labels; the coverage matrix lists 64 audited
repositories.** These are different populations and the difference is deliberate. The rule set
only names a framework when the source audit produced at least one deployable literal for it;
the other 20 audited repositories contributed no rule that survived the usability screen or the
real-traffic qualification, or are represented under a family or project label rather than a
repository name (the released set also contains two rules labelled `DSH-selfbuilt` for the
study's own in-house frameworks). Neither number should be read as "65 frameworks have rules".

---

## 8. Single-rule discrimination

Source: `data/aggregate/threshold_fpr_tradeoff.json` (`rule_discrimination` block), computed
over the 13 positive actors and 1,582 real attacker actors of the archived corpus.

| Rule | Positive coverage | Negative coverage | Discrimination |
|---|---:|---:|---:|
| E6 (pruning of dead branches) | 0.923 | 0.418 | 0.505 |
| E1 (structural scale) | 0.462 | 0.022 | 0.439 |
| E11 (404 tolerance) | 0.769 | 0.244 | 0.525 |
| E5 (route change after error) | 0.462 | 0.164 | 0.298 |
| E2 (machine speed x human thinking) | 0.231 | 0.157 | 0.073 |
| E12 (backtrack verification) | 1.000 | 0.000 (artefact) | not measurable |
| E3 (identity rotation) | 0.615 | 0.000 | 0.615 |
| E4 (machine naming) | 0.077 | 0.000 | 0.077 |
| E7 (enumeration breadth) | 0.769 | 0.030 | 0.740 |
| E9 (multi-channel orchestration) | 0.769 | 0.007 | 0.762 |
| E14 (dictionary brute-force discriminator) | 0.000 | 0.222 | reverse evidence |
| E15 (dictionary enumeration discriminator) | 0.000 | 0.001 | reverse evidence |

**E12's negative coverage of zero is a measurement artefact, not a property.** The WAF log
contains no successful responses, so the 2xx-response denominator of E12 is identically zero and
the rule cannot fire. Re-measured on the negative populations that do contain 2xx responses,
E12 fires on 6 of 6 released scanner actors (8 of 8 of the full source file). E12 is therefore
**not** a discriminator, and no
"E12 gating" is used to reduce the false-positive rate anywhere in this release.

The three rules that do separate AI agents from crawlers and scanners are **E9** (multi-channel
orchestration, 0.762), **E7** (enumeration breadth, 0.740) and **E3** (identity rotation, 0.615).
All three describe an agent *adjusting its next step in response to the previous response*,
rather than a rate, a volume or an error rate.

---

## 8b. A reproducibility caveat in the released engine

Re-scoring the published captures with the released engine does **not** reproduce two of the
published scores exactly. The cause is a one-character difference in the E9 boundary condition
between the engine that produced the study's numbers and the copy vendored into this repository.

| Capture | Published score | Re-scored score | Cause |
|---|---:|---:|---|
| DSH-1 | 0.8030 | 0.7762 | E9 did not fire |
| CyberStrikeAI-1 | 0.6576 | 0.6109 | E9 did not fire |
| the other 13 captures | identical | identical | - |

**The mechanism.** E9 requires several execution channels to be visible at once. The upstream
engine fires it when the actor uses **3 or more** user-agent families
(`f9_ua_families >= 3`); the vendored copy fires it only at **4 or more**
(`f9_ua_families > 3`). DSH-1 and CyberStrikeAI-1 each use exactly 3 user-agent families, so
the vendored engine drops E9 for them and their scores fall by the weight E9 carries
(0.12). All 13 other captures use 1, 2, 4, 5, 6 or 7 user-agent families and are unaffected.

**What it does and does not change.** The segmentation is identical for both captures (the
scored request counts match the published values exactly: 1,519 and 85), so this is a rule
condition and not a unit-of-analysis difference. The detection outcome does not change: both
scores stay above the 0.35 threshold, so segment recall remains 13/15 and framework recall
remains 10/12 under either boundary. On the negative population the effect is equally small:
2 of the 1,582 attacker actors change score, and one of them changes detection status
(0.3805 -> 0.2960, i.e. it falls below the threshold), which moves the false-positive count
from 43 to 42 rather than 43.

**Why the published figures are the ones reported here.** The published aggregate artefacts
(`data/aggregate/framework_detection.json`, `data/aggregate/threshold_fpr_tradeoff.json`)
and the CI check (`research/ci/check_headline_numbers.py`) were computed with the upstream
condition and are mutually consistent with each other; the CI check reads the aggregate files,
so it validates the published figures rather than re-deriving them from raw captures. The
numbers in this document are therefore the published ones. The divergence is recorded here
rather than silently reconciled, because the vendored copy is documented as a verbatim copy
whose only intended change was the removal of the external lab paths.

**Action for a reader.** If you re-score the captures with `research/pipeline/score_actor.py`
and compare against `data/positive/_index.json`, expect DSH-1 and CyberStrikeAI-1 to be
0.0845 and 0.0467 lower respectively than the published values. Every detection count, recall
figure and false-positive rate in this document is unaffected.

---

## 9. Reproducing this document

```bash
cd ai-agent-attack-signatures

# every headline number in this document and in the README
python -m research.ci.check_headline_numbers

# section 2 (recall with exact intervals)
python -m research.evaluation.evaluate_detection

# section 3 (leave-one-framework-out)
python -m research.evaluation.lofo

# section 4 (family ablation ceilings)
python -m research.evaluation.family_ablation

# section 5 (false positives and threshold sweep)
python -m research.evaluation.false_positive_eval
python -m research.evaluation.threshold_sweep

# section 6 (signature self-tests against the published scanner captures)
python -m research.ci.selftest_rules
```
