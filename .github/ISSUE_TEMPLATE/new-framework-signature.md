---
name: New framework signature
about: Submit a signature that identifies one AI attack framework on the target side
title: "[signature] <framework name>"
labels: [signature, new-framework]
assignees: []
---

A signature is accepted when it identifies **one framework** on the target side
and when the identification is verifiable from the framework source code.  The
audit that produced the shipped rule set reads the framework repositories and
traces a string from the source file to the request that reaches the target.

Please fill in every field.  A field that cannot be filled in usually means the
feature is not observable on the target side, and that is a useful answer too.

## Framework

| Field | Value |
|---|---|
| Framework name | |
| Repository URL | |
| Repository revision (commit or tag) | |
| Implementation language | |
| License of the upstream project | |

## The feature

| Field | Value |
|---|---|
| Feature value (the literal that appears on the wire) | |
| Where the value is observed (request header, request path, request body, TLS metadata) | |
| Field type (literal, regular expression, or a set of alternatives) | |
| Source location (file and line) | |
| How the value is produced at runtime (constant, template, tool invocation) | |
| Stability (constant / versioned / changes between releases) | |
| Is the value emitted by the framework itself, or by a tool it spawns? | |

## Evidence

- [ ] The value was read from the framework source at the revision given above.
- [ ] The source location points at the code that produces the request, not at a
      documentation example.
- [ ] The value is not a generic identifier that any client may send (browser
      user agents, common request headers, generic tool user agents).
- [ ] The value is not a source code template, a placeholder or a documentation
      string that is never sent.
- [ ] The scope is the target side, that is the value can appear in a request
      that the framework sends to the system under test.

## Traffic observed

If the framework was run against an evaluation environment, add what was
observed.  This is what turns a source-derived candidate into a validated
signature.

| Field | Value |
|---|---|
| Was the framework executed? | |
| Number of requests observed on the target side | |
| Number of requests carrying this value | |
| Which request header or field carried it | |

## Additional notes

