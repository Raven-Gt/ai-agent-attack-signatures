# Security Policy

## Reporting a vulnerability in this repository

If you find a security problem in the code, the CI configuration or the released data,
report it privately. Do not open a public issue.

Include: affected path, description, reproduction steps, and the impact you observed.

## Reporting a false positive

A T1 rule that fires on legitimate traffic is a correctness defect, not a security
vulnerability. Please file it as a `false-positive` issue - include a redacted sample of
the matching request.

## Responsible use

This repository contains defensive detection material and descriptive research findings.
It also documents, by necessity, how AI pentest agents behave and which strings identify
them. Do not use it to build or tune offensive tooling, to evade detection at scale, or to
target systems you are not authorised to test.

See `docs/THREAT_MODEL.md` for the authors' own analysis of the offensive/Defensive
trade-off and the maintenance model.
