# Release v1.0

First public release of the audited signature set, the behavioural detector and the
dataset that backs both.

## What is in this release

| Item | Count |
|---|---:|
| Audited AI pentest frameworks | 65 |
| Traffic signatures | 610 (T1 272 / T2 126 / T3 212) |
| Strong signatures (T1) by field | body 150, path 37, HTTP header 36, User-Agent 35, other 12, OAST 2 |
| Frameworks with a T1 signature at source level | 41 |
| Frameworks validated end-to-end as attributable on the target side | 10 |
| Live AI-agent captures | 15 actors / 12 frameworks / 211,547 requests |
| Scanner hard-negative captures | 6 actors / 999 requests |
| Real attacker actors (pseudonymised feature vectors) | 1,582 |
| Platform rule files | Elasticsearch KQL, Splunk SPL, Suricata, Sigma |
| Figures | 12 (PNG + PDF/SVG) |
| Research documents | 7 |

## Headline measurements

- T1 rules matched **0** of 9,905,794 public internet requests (80,987 source addresses)
  and **0** of 142,705 real WAF attack transactions.
- Exactly **1** of 80,987 source addresses matched two or more T1 rules.
- Behavioural detection: **13/15** segment recall, **10/12** framework recall,
  one-sided 95% lower bound **0.779**, leave-one-framework-out **9/10**.
- False positives: **2.72%** (95% CI [2.02%, 3.64%]) on 1,582 real attackers;
  **66.67%** on six scanner actors.

## Licensing

MIT for the repository. Signatures derived from copyleft-licensed upstream frameworks are
isolated under `signatures/agpl/` and carry their own AGPL-3.0 / GPL / LGPL terms.
See `NOTICE`.

## Known limitations

Read `docs/LIMITATIONS.md` before deploying. The three that matter most:

1. An agent that delegates to sqlmap, ffuf or nuclei is not distinguishable from a human
   running the same tool. Passive HTTP inspection alone cannot cover this case.
2. The scanner negative sample is ffuf-dominated (910 of 999 records), so the 66.67% figure
   characterises ffuf-style enumeration rather than a balanced multi-tool population.
3. Signatures decay as upstream frameworks change their own markers.
