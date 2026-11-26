# Contributing

Thanks for helping keep this usable. Two contributions matter most:

## 1. Submit your framework's own signatures

If you maintain an AI pentest framework, you know your markers better than a static
audit does. We audit by downloading repositories and reading source; that takes days per
refresh, and one UA change invalidates a rule.

Open an issue with the `new-framework-signature` template, or send a pull request that
adds a rule to `signatures/rules.json`. A usable rule needs:

| Field | Requirement |
|---|---|
| `framework` | The framework name |
| `field` | `user_agent` / `header` / `uri` / `body` / `oast_dns` / `other` |
| `pattern` | The literal or pattern as it appears **in the request**, not in the source |
| `source` | `path/to/file.py:123` in the upstream repository |
| `scope` | `target` for anything the target can observe |
| `stability` | How many upstream repositories share it (`1/1` means exclusive) |

Rules are validated in CI: the pattern must compile as a regex, must be free of `\s`
(Lucene/KQL incompatible), must not match a synthetic benign browser request, and must
not match anything in the public-traffic scan fixture.

**You may also ask us to remove a signature for your framework.** We will honour that
request and note the removal in the commit history.

## 2. Report stale signatures and false positives

- `stale-signature`: a rule that no longer matches
- `false-positive`: a T1 rule firing on legitimate traffic

False-positive reports are the most valuable input we get. Please include a redacted
sample of the matching request.

## 3. Contributing code

```bash
git clone <fork-url> && cd ai-agent-attack-signatures
python -m venv .venv && . .venv/Scripts/activate
pip install -r research/requirements.txt
pytest research/ -q
```

Please keep the CI assertions green - they assert the headline numbers in `README.md`.

## 4. Adding a framework to the coverage matrix

A framework counts as *attributable* only if it was run against a live target and its
own traffic was observed on the target side. Framework-level coverage and target-side
attributability are deliberately reported as two different numbers.

## Code of conduct

By participating you agree to abide by `CODE_OF_CONDUCT.md`.
