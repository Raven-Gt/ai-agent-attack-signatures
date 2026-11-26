# Roadmap

This project tracks two things separately: the **signature set** (which decays as upstream
frameworks change) and the **behavioural detector** (which needs more corpora). Both are
open to outside contributions - see `CONTRIBUTING.md`.

---

## Signature set

| | |
|---|---|
| Current | 610 rules across 44 framework labels; 272 tier-1 |
| Target | every framework with a target-side fingerprint has at least one tier-1 rule, and every tier-1 rule has been observed on real traffic at least once |

### In progress

- [ ] Extend the coverage matrix to the frameworks that were audited but never executed
      (see `data/aggregate/framework_coverage_matrix.csv`, `runtime_status = blocked`)
- [ ] Resolve the blockers recorded per framework so that more of them can be run end-to-end
      - several need an Anthropic-compatible or Responses-compatible endpoint
      - several need a second host (Kali, Mythic C2, SSH target)
      - several need an interactive TUI driven by a script rather than a flag
- [ ] Add a third validation corpus (an independent honeypot dataset) so the zero-hit claim
      is not resting on two sources

### Wanted from maintainers of the covered frameworks

- [ ] Confirm or correct the signatures extracted from your framework
- [ ] Submit markers the static audit missed (you know your agent better than a grep does)
- [ ] Tell us when a signature goes stale - we retire them rather than leave them to rot

## Behavioural detector

| | |
|---|---|
| Current | 103 features, 14 evidence rules, 86.7% segment recall at a 2.72% false-positive rate on 1,582 real attackers |
| Target | false-positive rate below 1% with a defensible confidence interval, which requires roughly 3,000 negative actors |

### In progress

- [ ] Grow the negative actor set from 1,582 to 3,000+ (the sample size is currently the
      binding constraint on any sub-1% claim, not the detector)
- [ ] Balance the scanner negative sample - it is currently ffuf-dominated (910 of 999
      records), so the 66.67% figure characterises one tool rather than a population
- [ ] Add a corpus with successful (2xx) responses: the WAF-derived negative set contains
      none, because a WAF records only the requests it flags
- [ ] Extend leave-one-framework-out beyond the ten frameworks that have been executed

### Explicitly out of scope

- [ ] Egress-side detection (LLM gateway correlation). Described in `docs/LIMITATIONS.md`,
      not implemented here, and the single most promising control for the tool-delegation
      blind spot.

## Releases

Quarterly. Each release carries a changelog, a rebuilt rule set and a re-run of the full
validation (public-traffic scan plus WAF corpus).

---

## Contributing

The highest-value contributions are not code:

1. **A framework maintainer confirming or correcting their own signatures.**
2. **A deployment report** - which rules fired, in what environment, and what the false
   positive rate looked like. These become the deployment evidence in the README.
3. **A negative corpus** that fills a gap listed above.
