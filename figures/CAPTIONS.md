# Figure captions

Paper-grade figures for **ai-agent-attack-signatures**. Every caption states
what the figure shows and the headline number it carries. All numbers are
reproducible from the artifacts in `data/` and `signatures/`; the PNG files
live in `figures/`, the vector (PDF/SVG) versions in `figures/vector/`.

Regenerate and re-check everything with:

~~~bash
python figures/build_figures.py     # renders PNG + PDF + SVG
python figures/verify_figures.py     # size / blank / vector / ASCII checks
~~~

---

1. **Figure 1 - Framework attribution matrix** (`fig01_framework_attribution_matrix.png`).
   One row per audited AI pentest repository (64 rows in the released coverage
   matrix), encoded on four columns: source audit present, indicator
   inventory present, how far the runtime execution got (captured / ran
   without own fingerprint / dry run only / blocked), and whether the
   framework leaves its own fingerprint on the target side (teal), only
   generic tool traffic (amber) or no target traffic at all (grey). The
   middle panel gives the size of each repository's class-A target-side
   indicator inventory; the right panels give the coverage funnel and the
   runtime-status x attribution cross-tab.
   **Headline: only 10 of the 64 audited repositories (16%) are attributable
   on the target side; 29 (45%) could be executed against the evaluation
   target and 35 were blocked before execution.**

2. **Figure 2 - Composition of the tier-1 signature set by request field**
   (`fig02_t1_signature_composition.png`). The 272 tier-1 rules of the
   combined 610-rule set (MIT 444 + AGPL 166) counted by the request field
   they match, with share of the tier-1 total, next to the tier split of the
   whole rule set and the indicator-kind breakdown of the tier-1 subset.
   **Headline: 150 of the 272 tier-1 rules (55.1%) match on the request
   body, 37 (13.6%) on the request path, 36 (13.2%) on a request header,
   35 (12.9%) on the User-Agent, 12 (4.4%) in other channels and 2 (0.7%)
   on an OAST domain.**

3. **Figure 3 - Per-framework attribution score and the two missed frameworks**
   (`fig03_per_framework_detection_score.png`). The AI attribution score of
   each of the 15 AI agent attack segments against the decision threshold
   tau = 0.35, with the request count of each segment, plus the detection
   outcome for segments and frameworks.
   **Headline: 13 of 15 segments (86.7%) and 10 of 12 frameworks (83.3%)
   reach tau = 0.35; the two misses are hackingBuddyGPT (0.280, only E5 and
   E12 fire) and pentest-ai (0.250, vetoed by the E15 reverse-evidence rule);
   the one-sided 95% lower bound for "all 12 frameworks detected" is
   0.05^(1/12) = 0.779.**

4. **Figure 4 - Threshold trade-off** (`fig04_threshold_tradeoff.png`). Left
   panel: segment (capture) recall and framework recall as a function of the
   decision threshold, recomputed on the released 15 captures over 12
   frameworks. Right panel: the false-positive rate on the 1,582 real
   attacker actors with its 95% Wilson interval, on a log scale. The chosen
   operating point is marked on both panels.
   **Headline: at tau = 0.35 the detector keeps 86.7% of the segments and
   83.3% of the frameworks while false-positiving on 43 of 1,582 real
   attackers (2.72%, 95% CI 2.02-3.64%); tau = 0.50 lowers the
   false-positive rate to 0.19% but drops segment recall to 73.3%.**

5. **Figure 5 - False-positive breakdown** (`fig05_false_positive_breakdown.png`).
   False-positive rate of the six negative populations of the study, with 95%
   Wilson intervals, next to the cumulative score distribution of the two
   headline populations (1,582 WAF attackers and 6 scanner containers).
   **Headline: 2.72% false positives on the 1,582 real attackers (43/1,582)
   against 66.67% on the six tool-driven scanner containers (4/6) - a 24.5x
   difference between the two attacker populations; the honeypot population
   stays at 0%.**

6. **Figure 6 - Feature-family ablation** (`fig06_feature_family_ablation.png`).
   Left panel: the recall upper bound that remains when each feature family
   is unavailable in the operator's logs. Right panel: the number of the 15
   segments that fall below tau when the family is removed.
   **Headline: the base recall upper bound is 0.933 (14 of 15 segments);
   removing F3 (feedback adaptivity) drops it to 0.733 (-20.0 points, 3
   segments lost), removing F6 (repetition and verification) costs 1 segment
   (0.867), and the other five families cost nothing.**

7. **Figure 7 - Leave-one-framework-out recall**
   (`fig07_leave_one_framework_out.png`). Left panel: recall on the held-out
   framework for each of the 10 folds, with the threshold calibrated on the
   other nine frameworks. Right panel: the one-sided 95% lower bound
   0.05^(1/k) of the generalisation claim as a function of the framework
   count k.
   **Headline: 9 of the 10 folds reach recall 1.000 (90.0%) with 0 false
   positives in every fold (56 negative actors, 95% Wilson upper bound
   6.42%); the single failure is hackingBuddyGPT, whose score (0.280) falls
   below the threshold calibrated on the other nine frameworks (tau = 0.4146).**

8. **Figure 8 - Rule validation on real traffic**
   (`fig08_rule_validation_real_traffic.png`). Left panel: the 16 rules that
   matched on 9,905,794 public internet requests, with the number of matched
   requests and source addresses on a log scale, coloured by tier. Top right:
   the tier-1 validation result for the public-traffic scan and for the
   30-day ModSecurity WAF audit log. Bottom right: the number of source
   addresses that matched one, two or more rules.
   **Headline: tier-1 rules matched 0 of 9,905,794 public requests (80,987
   source IPs) and 0 of 142,705 real WAF attack transactions; all 16 rules
   that did match on public traffic are tier 2 or tier 3, and exactly 1 of
   the 80,987 source addresses matched 2 or more rules (31 matched exactly
   one).**

9. **Figure 9 - Evidence-rule weights and family conviction**
   (`fig09_evidence_rule_weights.png`). Left panel: the weight of each of the
   15 evidence-rule identifiers E1-E15, coloured by the feature family the
   rule reads; E10 (weight 0.95) needs response-side data and is shown
   clipped, E13 was withdrawn after real-traffic validation, and E14/E15 are
   reverse-evidence rules with zero conviction weight. Right panel: the
   conviction weight that a whole family can reach on its own.
   **Headline: the largest single-rule weight is 0.34 (E1, exploration), below
   the 0.35 decision line, so no single rule can convict an actor; but the
   three feedback-adaptivity rules of family F3 together reach 0.4086, i.e.
   above the decision line.**

10. **Figure 10 - AI agent versus scanner behaviour**
    (`fig10_ai_agent_vs_scanner_behaviour.png`). The 15 AI agent actors, the
    6 scanner containers and the 1,582 real attackers in one plot of request
    rate against endpoint breadth, plus the cumulative distributions of both
    variables. Endpoint templates are the shipped endpoint templating
    (numbers, UUIDs, hashes and mail addresses folded into {id}); the
    request-rate axis is capped at 20,000 requests per minute, above which
    the real-attacker curve is already flat at 100%.
    **Headline: the four scanner actors that were flagged sit inside the
    request-rate and endpoint-breadth range of the AI agent actors, which is
    the mechanical reason for the 66.67% scanner false-positive rate.**

11. **Figure 11 - The 15 AI agent attack segments**
    (`fig11_ai_actor_timeline.png`). Left: attack duration against
    attribution score, the bubble area showing the request volume, with the
    decision threshold marked. Right: the scored request volume per actor.
    **Headline: a single capture (strix, 31,024 of the 54,900 scored agent
    requests, 57%) carries more than half of all scored agent traffic, and
    the two missed frameworks are the two thinnest actors in the set
    (hackingBuddyGPT with 62 requests, pentest-ai veto-capped at 0.250).**

12. **Figure 12 - Which feature families carry the decision**
    (`fig12_feature_family_profile.png`). Left: the mean conviction weight
    each feature family contributes, for the AI agent actors, the scanner
    actors and the 1,582 real attackers. Right: how often each evidence rule
    fires in the three populations.
    **Headline: the flagged scanner actors fire the shared rules E5, E6, E7,
    E11 and E12 (plus E9 for three of them) and those five rules alone sum
    to 0.542, already above the 0.35 decision line - which is why 66.67% of
    the scanner actors are flagged.**

---

## Provenance

| Figure | Source artifacts |
|---|---|
| 1 | `data/aggregate/framework_coverage_matrix.json` |
| 2 | `signatures/rules.json`, `signatures/agpl/rules-agpl.json` |
| 3 | `data/aggregate/framework_detection.json` |
| 4 | `data/aggregate/threshold_fpr_tradeoff.json` |
| 5 | `data/aggregate/negative_set_summary.json`, `data/features/actor_features.jsonl`, `data/negative/_index.json` |
| 6 | `data/aggregate/feature_family_ablation.json`, `data/aggregate/framework_detection.json` |
| 7 | `data/aggregate/lofo_framework.json` |
| 8 | `data/aggregate/rule_validation_counts.json` |
| 9 | `research/engine/evidence.py` (shipped evidence rules) |
| 10 | `data/positive/*/access.jsonl`, `data/negative/*/access.jsonl`, `data/features/actor_features.csv` |
| 11 | `data/aggregate/framework_detection.json`, `data/positive/*/meta.json` |
| 12 | `data/aggregate/framework_detection.json`, `data/negative/_index.json`, `data/features/actor_features.jsonl` |

## Notes on two counts that are easy to misread

* **64, not 65.** The released framework coverage matrix
  (`data/aggregate/framework_coverage_matrix.json`) has 64 audited
  repositories, and that is the number Figure 1 plots. The repository README
  quotes "65 audited AI-pentest codebases" as its headline; the rule-set
  artifact explains the difference: the rule set references 44 distinct
  framework labels, and the coverage matrix lists 64 audited repositories.
  The gap is made up of repositories that contributed no rule and of
  synthetic labels used for the project's own components.
* **13 of 15 versus 10 of 12.** The threshold trade-off artifact was produced
  against an earlier positive set of 13 captures over 10 frameworks; the
  recall columns of Figure 4 are recomputed on the released 15 captures over
  12 frameworks (the shipped `recomputed_on_released_set` block), while the
  false-positive columns are unchanged because the negative population did
  not change.

## Style

* matplotlib only, DejaVu Sans throughout, no seaborn.
* Colour-blind safe palette: #2E5EAA (blue), #D1495B (red), #2A9D8F (teal),
  #E9C46A (amber), #6C757D (grey); the four accents differ strongly in
  luminance, so every figure stays readable in greyscale. Ordinal scales
  (runtime status) use a single-hue blue ramp, nominal scales use the accents.
* No top/right spines, horizontal gridlines only, legend frames removed.
* Label fonts >= 10 pt, axis titles 12-12.5 pt, figure titles 15 pt bold.
* Every figure is exported as PNG (150 dpi, README) and as PDF and SVG
  (`figures/vector/`, paper).
