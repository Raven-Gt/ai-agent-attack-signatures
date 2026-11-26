# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-26

First public release.

### Added

- **Signature set**: 610 rules extracted from 65 audited AI-pentest codebases (64 third-party
  frameworks plus one in-house implementation), tiered by attributability:
  - T1 (272): framework-exclusive, target-observable, zero hits on both real corpora - deploy these
  - T2 (126): generic attack semantics - attack evidence only
  - T3 (212): generic tooling identifiers, over-broad patterns, and rules that cannot occur
    in real traffic - excluded from deployment
- **Platform exports**: Elasticsearch/OpenSearch KQL, Splunk SPL, Suricata/Snort, Sigma
  (webproxy). 283 deployable rules per platform in the MIT set, 99 in the copyleft set.
- **Rule-usability screen**: source-code templates, placeholder tokens, descriptive text mixed
  into literals, example hostnames, weak credentials, command templates and identifier lists
  are detected and excluded (68 rules removed at the time of writing).
- **Behavioural detector**: actor-level decision unit, 103 features across 11 families, 14
  evidence rules (E1-E12, E14, E15) fused with a noisy-OR model, reverse-evidence veto.
- **Datasets**: 15 live AI-agent captures (211,547 requests, 12 frameworks), 6 scanner
  hard-negative captures (999 requests), 1,582 pseudonymised real-attacker feature vectors,
  15 aggregate tables, a dataset card and a checksum manifest.
- **Research documents**: methodology, experiment protocol, results, framework coverage
  matrix, limitations and threat model, plus a full paper.
- **12 figures** in PNG and vector form with a caption file carrying the headline number of
  each.
- **Reproducible pipeline** with continuous integration asserting every headline number in
  the README against the shipped artefacts.

### Measurements

- T1 matched **0** of 9,905,794 public internet requests (80,987 source addresses) and
  **0** of 142,705 real WAF attack transactions spanning 30 days.
- Exactly **1** of 80,987 source addresses matched two or more T1 rules.
- Behavioural detection: **13/15** segment recall, **10/12** framework recall, one-sided 95%
  lower bound **0.779**, leave-one-framework-out **9/10**.
- False positives: **2.72%** (95% CI [2.02%, 3.64%]) on 1,582 real attacker actors;
  **66.67%** on six scanner actors.

### Known limitations

See `docs/LIMITATIONS.md`. The three that matter most:

- An agent that delegates to sqlmap, ffuf or nuclei is indistinguishable from a human
  running the same tool; passive HTTP inspection cannot cover that case.
- The scanner negative sample is ffuf-dominated (910 of 999 records), so the 66.67% figure
  characterises ffuf-style enumeration rather than a balanced multi-tool population.
- Signatures decay as upstream frameworks change their own markers.

### Licensing

MIT for the repository. Signatures derived from copyleft-licensed upstream frameworks are
isolated under `signatures/agpl/` and carry their own AGPL-3.0 / GPL / LGPL terms; see
`NOTICE`.
