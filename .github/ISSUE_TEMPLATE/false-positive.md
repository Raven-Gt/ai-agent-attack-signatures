---
name: False positive
about: Report a tier-1 rule that fires on legitimate traffic
title: "[false positive] <rule id> on <traffic description>"
labels: [signature, false-positive]
assignees: []
---

Tier-1 rules are the framework fingerprints that are meant to be deployed on
their own, so a tier-1 rule that fires on legitimate traffic produces an alert
that a responder has to dismiss.  Every such report is a defect in the shipped
rule set, and it is fixed by removing or narrowing the rule.

## The rule

| Field | Value |
|---|---|
| Rule id | |
| Field (user agent, path, header, body) | |
| Pattern as shipped | |
| What matched | |

## The traffic

| Field | Value |
|---|---|
| Description of the traffic | |
| What kind of client or application sent it | |
| Number of requests inspected | |
| Number of requests that matched | |
| Traffic source | |
| Sample (redacted) | |
| Does the traffic contain any framework identifier, or only a generic pattern? | |

## Assessment

- [ ] The matching traffic is legitimate and not an attack.
- [ ] The rule was checked against the public traffic scan and against the real
      WAF attack transactions, and this traffic was not part of either corpus.
- [ ] The pattern is a generic identifier (a browser user agent, a common
      request header, a generic tool user agent) rather than a framework marker.

## Proposed action

- [ ] demote the rule to tier 2
- [ ] demote the rule to tier 3 (retired, not deployable)
- [ ] narrow the pattern
- [ ] add the pattern to the list of generic identifiers

