# Pull request

## What this changes

<!-- One paragraph. Which rule set, which platform file, which number. -->

## Type of change

- [ ] new signature for a framework
- [ ] narrowed or demoted signature
- [ ] retired signature
- [ ] change of the platform rule files
- [ ] change of the research pipeline or of the evaluation code
- [ ] change of the documentation

## Checklist for a signature change

- [ ] **The source location was verified.** The pattern was read from the
      framework source at the revision given in the pull request, at the line
      that produces the request and not at a documentation example.
- [ ] **The scope is the target side.** The value can appear in a request that
      the framework sends to the system under test, and not only in the traffic
      that the framework sends to itself or to a third party.
- [ ] **The rule was tested against the public traffic scan.** The new rule was
      run over the published public internet traffic and over the published real
      WAF attack transactions, and the number of tier-1 hits stays at zero.
- [ ] **No generic tooling user agent.** The pattern is not a generic client
      identifier such as a browser user agent, a scanner user agent or a common
      request header.  Generic identifiers belong to tier 2 or tier 3.
- [ ] **No source code template.** The pattern is not a placeholder, a template
      or a documentation string that is never sent on the wire.
- [ ] **The tier is right.** Tier 1 means the value identifies one framework and
      can be deployed on its own; tier 2 means the value proves an attack but
      does not separate an AI agent from a script; tier 3 means the value is
      generic and is not deployable.
- [ ] **The license of the upstream project is recorded**, and the rule was
      placed in the MIT subset or in `signatures/agpl/` accordingly.

## Checklist for a change of the platform rule files

- [ ] The rule count of every platform file matches the rule set that the
      platform can express, and the CI check passes.
- [ ] No deployed expression contains `\s`, because Lucene and KQL have
      no `\s` operator.
- [ ] No platform rule has an empty pattern.

## Checklist for a change of the research code

- [ ] The unit tests pass: `python -m pytest research/tests -q`.
- [ ] Every number in the README that the change affects is recomputed by
      `python -m research.ci.check_headline_numbers --readme README.md`.
- [ ] The change does not alter a published number without the number being
      updated in the README and in `data/aggregate/`.

## Reviewer notes

<!-- Anything a reviewer should look at first. -->
