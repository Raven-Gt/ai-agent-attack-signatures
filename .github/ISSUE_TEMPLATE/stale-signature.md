---
name: Stale signature
about: Report a shipped signature that no longer matches
title: "[stale] <rule id> - <framework name>"
labels: [signature, stale]
assignees: []
---

A shipped signature that no longer matches is not a minor defect: a rule that
never fires is dead weight in a deployment, and a rule that fires on the wrong
traffic is a false alarm.  Both are worth reporting.

## The rule

| Field | Value |
|---|---|
| Rule id | |
| Framework | |
| Tier (T1, T2, T3) | |
| Field (user agent, path, header, body) | |
| Pattern as shipped | |

## Observation

| Field | Value |
|---|---|
| What was expected | |
| What was observed instead | |
| Traffic source (own evaluation environment, public dataset, honeypot, other) | |
| Number of requests inspected | |
| Number of requests matching the rule | |
| First observation date | |
| Last observation date | |

## Analysis

- [ ] The upstream project was checked for a change of the marker (release notes,
      changelog, diff against the revision the rule was derived from).
- [ ] The framework was re-run, or a recent capture was inspected, to confirm
      that the marker no longer appears.
- [ ] The failure is not caused by a change in the measurement itself (a
      different log format, a missing request body, a proxy in the path).

## Proposed action

- [ ] retire the rule
- [ ] narrow the rule (new tier, narrower field, tighter expression)
- [ ] keep the rule and document the conditions under which it does not fire

