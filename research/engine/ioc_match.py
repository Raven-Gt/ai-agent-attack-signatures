"""One authoritative matching semantics for the IOC rules.

The generator, the validator and the platform rule files all call this module.

Why this layer exists:
----------------------
Two serious defects happened before, both caused by the generation semantics and
the validation semantics not being the same code:
  1. the deployed files were written as empty rules (syntax() read the wrong
     field) while the self-check only counted rules and never looked at them;
  2. a literal containing * or [ was treated as a regular expression
     metacharacter (cs* became c followed by zero or more s), the validator
     compiled the literal directly while the deployed file used the escaped
     expression, so the two did not agree.
This module provides the single authoritative implementation:
  deploy_regex(rule) -> str   the deployed expression (literals escaped,
                               placeholders written as [^ \t/]+)
  compile_rule(rule) -> (regex, field)
  match_sample(rule, sample) -> bool
r"""
from __future__ import annotations

import re

FIELD_OF = {
    "UA": "user_agent", "HEADER": "header", "PATH": "uri",
    "PAYLOAD": "body", "CRED": "body", "OAST": "oast_dns",
}


PLATFORM_COMPAT = [(r"\s", r"[ \t]")]


def _platform_compat(rx: str) -> str:
    r"""Platform compatibility: Lucene and KQL have no \s operator, so it is
    replaced everywhere by a space plus tab character class.

    Why this step is needed: exact rules first pass through re.escape(), which
    turns [^\s/] into \[\^\\s/\].  A literal replacement then no longer
    matches, \s survives into the deployed file, and the rule silently never
    fires on those platforms.
    """
    for a, b in PLATFORM_COMPAT:
        rx = rx.replace(a, b)
    return rx


def deploy_regex(rule: dict) -> str:
    r"""The deployed regular expression.

    - match=regex: the expression computed at generation time (already
      re.escape()d, with the angle-bracket placeholder written as [^\s/]+)
    - match=exact: the literal is escaped, with * used as a placeholder and
      written as [^ \t/]*
    - \s inside a character class becomes a space plus tab, because Lucene and
      KQL do not support \s
    """
    if str(rule.get("match")) == "regex" and rule.get("regex"):
        return _platform_compat(str(rule["regex"]).replace(r"[^\s/]", r"[^ \t/]"))
    pat = str(rule.get("pattern") or "")
    parts = [p for p in pat.split(" / ") if p.strip()]
    outs = []
    for p in parts:
        p = p.replace("*", r"[^ \t/]*")
        outs.append(re.escape(p))
    if not outs:
        return ""
    joined = outs[0] if len(outs) == 1 else "(?:" + "|".join(outs) + ")"
    return _platform_compat(joined)


def compile_rule(rule: dict):
    """Return (compiled_regex, field), or (None, field) when there is none."""
    f = FIELD_OF.get(str(rule.get("kind")), str(rule.get("field") or ""))
    src = deploy_regex(rule)
    if not src:
        return None, f
    try:
        return re.compile(src, re.I), f
    except Exception:
        return None, f


def value_of(sample: dict, field: str) -> str:
    """Return the text of the matching field of one request sample."""
    if field == "user_agent":
        return str(sample.get("ua") or "")
    if field == "uri":
        return str(sample.get("uri") or "")
    if field == "body":
        return str(sample.get("body") or "")
    if field == "header":
        return str(sample.get("hdr") or "")
    return ""


_COMPILE_CACHE = {}
def compiled(rule: dict):
    """Compilation with a cache (rule objects do not change inside one run, and recompiling is 100 times slower)."""
    key = id(rule)
    if key not in _COMPILE_CACHE:
        _COMPILE_CACHE[key] = compile_rule(rule)
    return _COMPILE_CACHE[key]

def match_sample(rule: dict, sample: dict) -> bool:
    """Match one request sample against one rule."""
    rx, f = compiled(rule)
    if rx is None:
        return False
    s = value_of(sample, f)
    if not s:
        return False
    return bool(rx.search(s))
