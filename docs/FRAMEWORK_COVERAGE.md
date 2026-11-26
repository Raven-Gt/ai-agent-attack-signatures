# Framework coverage matrix

**The central result of this study, and the number that constrains every other claim in it.**

> Source-level coverage and target-side coverage are different populations, and the gap between
> them is the finding.
>
> * **64 repositories** were read at source level and produced an indicator inventory.
> * **41 framework labels** carry at least one tier-1 (framework-exclusive) signature.
> * **10 frameworks** were validated end to end as attributable on the target side.

Why the three numbers differ is explained in section 3. This document does not claim that 65
frameworks have deployable signatures.

Source: `data/aggregate/framework_coverage_matrix.json`
(`data/aggregate/framework_coverage_matrix.csv`), `data/aggregate/rule_validation_counts.json`,
the per-rule provenance in `signatures/rules.json` (each rule carries its `framework`,
`source` and `stability` fields) and `data/aggregate/framework_coverage_matrix.csv`.

---

## 1. The matrix

Legend for **Own target-side fingerprint**:

* **Yes** — the framework's own HTTP client leaves a framework-exclusive literal on the target
  side, and this was observed in a real run against the evaluation target.
* **Own client, generic tool traffic** — the framework has its own client, but in practice the
  traffic that reaches the target is emitted by general-purpose tooling it invokes
  (curl / sqlmap / ffuf / nuclei), so the target sees a generic tool identity.
* **No** — the framework has no framework-owned target-side signal: either it has no target-facing
  HTTP client of its own, or its own client produces only generic identities.

The **Language / stack** column is derived from the source-file extensions cited in each
framework's indicator inventory and cross-checked against the audit report. Where the inventory
contains no code-file reference, the entry is marked accordingly rather than guessed.

| # | Framework | Language / stack | IOC features | Class-A target-side | Own target-side fingerprint | Target-side attribution | Validation | Blocking reason or note |
|---:|---|---|---:|---:|---|---|---|---|
| 1 | AI-OPS | Python | 21 | 18 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Container and model gateway run succeeded, but /model reports tool_use:false, so the full attack turn did not complete. |
| 2 | AIDA | Python | 5 | 3 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires starting the back end, the database, registration and login, and creating an assessment; not a single command. |
| 3 | ARTEMIS | Rust | 32 | 26 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | base_url is hard-coded; 6 source changes plus a 10-40 minute Rust build. |
| 4 | ARTEX-main | Go + Python | 11 | 4 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; the native Go request user agent is norma/0.4; in practice the worker drives bash and then curl. |
| 5 | AutoPT | Python | 2 | 0 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.415. |
| 6 | AutoPentester | Python | 0 | 0 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Requires interactive driving plus a first RAG run of 10 minutes; the full turn did not complete. |
| 7 | BugTraceAI | not measured (shell bootstrap only; submodules empty) | 0 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The repository is only an ecosystem meta-repository; all 5 submodules are empty. |
| 8 | Cairn | Python | 1 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The codex worker hard-codes the responses protocol; the pi worker has to be used instead. |
| 9 | CyberStrike | TypeScript / Node.js | 17 | 14 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; own user agent cyberstrike/2.0.0; the target-side webfetch path uses a Chrome user agent. |
| 10 | CyberStrikeAI | Go | 15 | 15 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.658. |
| 11 | Cybermes | Go | 25 | 19 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, own fingerprint present in the client, no target traffic captured this round | Go net/http direct calls with own user agents Cybermes/2.1 (Security Assessment) / (Recon Crawler) / Cybermes/3.2 (API Fuzzer) and a fixed Accept: */*; go build verified, but no target traffic was captured in this round. |
| 12 | Dark-Moon | Python | 23 | 21 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Image registry blocked; a local build needs oven/bun, which has no reachable source. |
| 13 | Decepticon | Python | 45 | 30 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | TUI only, plus a 10-20 GB stack. |
| 14 | HackSynth | Python | 0 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Four hard blockers: ImportError, a Neptune account, the Kali image, and a model name restricted to gpt-o1. |
| 15 | Incalmo | Python | 19 | 10 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The Kali image is unreachable and the equifax environment is hard-coded, so it cannot be pointed at the evaluation target. |
| 16 | LuaN1aoAgent | TypeScript / Node.js + Go + Python | 5 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires Node 25 or later and two image builds. |
| 17 | NeuroSploit | Rust | 23 | 20 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The Rust build takes 1-3 hours and crates.io is very slow; not completed in this round. |
| 18 | PentAGI | Go | 5 | 0 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 2 actor captures, best score 0.774. |
| 19 | Pentest-Swarm-AI | Go | 35 | 24 | No | No - no framework-owned target-side signal | dry run only (no attack turn) | A scan --dry-run completed the whole flow in 16 seconds and consumed real model tokens; the full attack turn was not run (16 external tools missing). |
| 20 | PentestGPT | Python | 5 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires an already signed-in Claude Code or Codex CLI; the legacy route never touches the target. |
| 21 | PentesterFlow | TypeScript / Node.js | 34 | 16 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.506. |
| 22 | Pojun | Go | 28 | 19 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; the enrich probe user agent was changed to Chrome/131 and no longer exposes a framework identifier. |
| 23 | T3MP3ST | TypeScript / Node.js | 25 | 20 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | An approval gate must be passed first; the operator value has to be aligned. |
| 24 | VulnBot | Python | 6 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires a separate SSH-reachable Kali attack host; the framework itself issues no HTTP to the target. |
| 25 | Zen-Ai-Pentest | Python | 25 | 19 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | https:// is hard-coded, so the code must be changed for an HTTP target; the traffic is entirely from tools such as nuclei. |
| 26 | agent-zero | Python | 3 | 1 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Not a penetration-testing framework; the image cannot be pulled. |
| 27 | airecon | Python | 45 | 39 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | not runnable (blocker recorded) | A Kali sandbox is built at start-up and the kalilinux image is unreachable locally; the framework itself uses httpx and has 39 class-A target-side features. |
| 28 | antifox | Go + Python | 12 | 4 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, 2799 records, score 0.617. |
| 29 | apex | TypeScript / Node.js | 9 | 4 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; the framework's own user agent is pensar-apex, but only 6 target-side samples were captured, too few to form an independent actor. |
| 30 | aracne | Python | 14 | 10 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The architecture only supports SSH targets; the HTTP evaluation target has no SSH. |
| 31 | ares | Rust | 5 | 1 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Dedicated to Active Directory and Windows domains; it produces no web attack traffic. |
| 32 | artex | Go + Python | 9 | 3 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully after a one-line patch to build; own user agent artex-enrich/1.0. |
| 33 | autopentest | Python | 0 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Playwright browser download is large; it runs nmap at start-up. |
| 34 | autopentest-ai | Python | 18 | 17 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The Docker build needs a dozen GitHub repositories cloned. |
| 35 | blacksmith | Python | 2 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The mini-kali image is blocked and the embedding interface gateway does not support it. |
| 36 | cai | Python | 0 | 0 | No | No - no framework-owned target-side signal | real run, no framework fingerprint observed | REPL/HTTP API shape; the audit confirmed only 1 T1 rule (an Accept string containing application/pdf); the main path is the model writing Kali shell curl commands on the fly. |
| 37 | cain-agent | Python | 33 | 29 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The default Claude backend is unavailable; --backend pi is required. |
| 38 | cyber-harness | Go | 18 | 11 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; own user agent cyber / compatible; cyber/1.0. |
| 39 | deadend-cli | Python | 19 | 17 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | not runnable (blocker recorded) | The first run needs the presetup wizard and a pre-seeded config.json; Docker and Playwright are also required. |
| 40 | echidna | Python | 16 | 3 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | A Mythic C2 server is required; the repository only ships the agent side. |
| 41 | forang | Go + Python | 16 | 5 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully (a Norma dependency must be cloned first); own user agents FORANG-DirScan and FORANG-Repeater. |
| 42 | guardian-cli | Python | 9 | 9 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Installation and --help were verified, but the built-in blacklist rejects every local address in a fail-closed manner, so no actual attack was performed. |
| 43 | hackingBuddyGPT | Python | 25 | 14 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.280. |
| 44 | hexstrike-ai | Python | 28 | 26 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; own user agent HexStrike-HTTP-Framework/1.0. |
| 45 | mapta | Python | 0 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | The repository lacks the function_tool module and depends on the Responses API. |
| 46 | nebula | Python | 14 | 0 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | not runnable (blocker recorded) | There is no pure command-line one-shot run; a provider profile and an engagement must be created first; chromadb and Playwright installs are heavy. |
| 47 | numasec | TypeScript / Node.js | 16 | 13 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; webfetch uses a Chrome user agent, and on a Cloudflare 403 fallback the user agent becomes numasec. |
| 48 | pentest-ai | Python | 28 | 23 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.250. |
| 49 | pentest-ai-agents | not measured (prompt package only) | 11 | 11 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires a paid Claude Code account; in substance it is a prompt pack rather than a tool. |
| 50 | pentest-copilot | TypeScript / Node.js | 14 | 8 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | A separate SSH-reachable Kali attack host is mandatory. |
| 51 | pentestagent | Python | 4 | 3 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires Playwright Chromium; the tool set has no HTTP tool, so all traffic comes from the shell. |
| 52 | pentestcode | TypeScript / Node.js | 29 | 25 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | The binary runs (--version 0.2.6) but the full attack turn did not complete. |
| 53 | raptor | Python | 44 | 32 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.428. |
| 54 | redamon | Python | 18 | 12 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Deployment takes 30-60 minutes and 20+ containers. |
| 55 | redcell | Python | 12 | 3 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | A 6-container stack whose LLM provider configuration can only be stored in the database. |
| 56 | sage | Python | 17 | 9 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | A Mythic C2 plugin whose README explicitly forbids direct connections to targets. |
| 57 | sapper-v2 | Python | 18 | 18 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Requires a self-hosted answer-platform API and the Anthropic protocol. |
| 58 | scopeweaver | Go | 7 | 2 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; the framework itself produced almost no target-side traffic (the attack traffic is entirely generated by the model invoking curl/nmap/ffuf). |
| 59 | shannon | TypeScript / Node.js | 17 | 15 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully, but the target-side traffic comes from Chromium and curl inside the container; the native framework only speaks Temporal gRPC. |
| 60 | strix | Python | 23 | 2 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.798. |
| 61 | virga | Go | 7 | 0 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | A C2 framework rather than a scanner; the server side does not compile and it has no request path to the target. |
| 62 | vulnerator-ai | Python | 3 | 2 | No | No - no framework-owned target-side signal | not runnable (blocker recorded) | Deployment takes 30-60 minutes, 20+ containers and gigabyte-scale images. |
| 63 | xalgorix | Go | 32 | 28 | Yes | Yes - own fingerprint, validated end to end | real run, traffic captured | 1 actor capture, score 0.540. |
| 64 | ycode-auto-pentest | Go | 24 | 8 | Own client, generic tool traffic | Partial - own client, but only generic tool traffic observable | real run, no framework fingerprint observed | Ran successfully; own user agents YCode-recon/0.3 and the X-YC-Junk header. |

---

## 2. Aggregates

### 2.1 By target-side attribution

| Attribution | Repositories | Share of 64 |
|---|---:|---:|
| Yes - own fingerprint, validated end to end | 10 | 15.6% |
| Partial - own client, but only generic tool traffic observable | 20 | 31.3% |
| No - no framework-owned target-side signal | 34 | 53.1% |
| **Total** | **64** | **100%** |

### 2.2 By validation status

| Validation | Repositories | Share of 64 |
|---|---:|---:|
| Real run against the evaluation target, traffic captured | 10 | 15.6% |
| Real run succeeded, no framework fingerprint observed in the traffic | 17 | 26.6% |
| Real run succeeded, own client fingerprint present, but no target traffic captured this round | 1 | 1.6% |
| Dry run only (`scan --dry-run`; no attack turn) | 1 | 1.6% |
| Not runnable - blocker recorded and archived | 35 | 54.7% |
| **Total** | **64** | **100%** |

### 2.3 The three headline aggregates

| Question | Answer |
|---|---|
| How many frameworks are attributable **on the target side**? | **10** - and only these 10 were confirmed by an actual run |
| How many produce **only tool traffic** on the target side? | **20** marked *partial* plus the 35 that could not be run: their source audits show the same pattern, the target would see a generic tool identity |
| How many **cannot produce HTTP target traffic at all**? | **10** - documented individually in section 4 |

The 10 frameworks that cannot produce HTTP target traffic at all are: `ares` (an
AD/Windows domain framework that produces no Web attack traffic), `aracne` (its architecture
supports only SSH targets), `virga` (a C2 framework, not a scanner; the framework itself has no
request path to a target), `sage` (a Mythic C2 plugin whose README forbids connecting directly
to targets), `VulnBot` (the framework itself issues zero HTTP to the target), `pentestagent`
(the tool set has no HTTP tool; all traffic comes from the shell), `pentest-ai-agents` (a prompt
package, not a tool), `agent-zero` (not a penetration-testing framework), `BugTraceAI` (an
ecosystem meta-repository whose five submodules are all empty) and `echidna` (it needs a Mythic
C2 server; the repository ships only the agent side). These are documented in the
`not_found` section of each framework's audit report.

### 2.4 Why the three headline numbers differ from each other

| Population | Count | What it is |
|---|---:|---|
| Audited repositories | 64 | Every repository that was downloaded and read at source level, whether or not it produced a usable signature |
| Distinct framework labels in the released rule set | 44 | Labels that carry at least one rule of any tier |
| Framework labels carrying at least one tier-1 rule | 41 | Labels that carry a framework-exclusive signature |
| Frameworks validated end to end as attributable on the target side | 10 | Confirmed by an actual run against the evaluation target |

The released rule set contains **610 rules over 44 distinct framework labels**; the coverage
matrix lists **64 audited repositories**. The difference is made up of repositories that
contributed no rule that survived the usability screen and the real-traffic qualification, and
of the `DSH-selfbuilt` label used for the study's two in-house frameworks.

21 of the 64 audited repositories contribute no rule under their own name: `ARTEX-main`,
`AutoPT`, `AutoPentester`, `BugTraceAI`, `Cairn`, `HackSynth`, `PentAGI`,
`PentestGPT`, `PentesterFlow`, `VulnBot`, `antifox`, `ares`, `artex`, `autopentest`,
`blacksmith`, `cai`, `forang`, `mapta`, `nebula`, `virga`, `ycode-auto-pentest`.
Three further labels carry only tier-2 and tier-3 rules (`LuaN1aoAgent`, `redcell`,
`vulnerator-ai`).

**This is the point that a rule-count headline would hide.** Five of the ten end-to-end
validated frameworks (DSH, PentAGI, PentesterFlow, AntiFox, ARTEX) contribute *no* tier-1 rule
under their repository name in the released set, and two of them (DSH, PentAGI) are the study's
own in-house frameworks, whose measured user agents are published under the `DSH-selfbuilt`
label. A catalogue that reported "65 frameworks, N rules" would overstate attribution
capability by a factor of six.

---

## 3. Source-level coverage versus target-side observability

The distinction has to be made explicit because the two numbers answer different questions:

**Source-level coverage (41 frameworks with tier-1 rules)** answers: *for how many frameworks
does a framework-exclusive literal exist in the source?* This is a property of the audit. It is
a necessary but not sufficient condition for deployment.

**Target-side observability (10 frameworks validated end to end)** answers: *for how many
frameworks was a framework-exclusive literal actually observed in traffic arriving at the
evaluation target?* This is a property of the runtime.

The gap has two distinct causes, and they should not be conflated:

1. **The framework never emits its own identity.** The audit of 9 of the 64 repositories found no
   target-facing HTTP client at all: the agent drives a shell and the shell runs
   `curl` / `sqlmap` / `ffuf` / `nuclei`. The target sees the tool, not the framework.
   This was confirmed empirically, not merely read: for AntiFox and ARTEX the static audit
   predicted own user agents (`antifox/1.0`, `norma/0.4`, `artex-enrich/1.0`) and the
   measured traffic contained none of them, only `curl/8.18.0`, `Python-urllib/3.12` and
   `inj-probe/1.0`. For strix, whose own system prompt explicitly forbids any identifiable
   marker, the framework's identity was absent from all 31,024 requests.
2. **The framework could not be run in this environment.** 35 repositories were blocked by
   build, image-registry, credential or model-gateway problems. Their blocking reasons are
   recorded individually in the matrix above and in each audit report, so that a later run can
   pick them up without repeating the triage.

Neither cause is a defect in the audit. Both are properties of the frameworks.

---

## 4. Validation method per framework

| Validation state | Repositories | What it establishes |
|---|---:|---|
| Real run, traffic captured | 10 | The framework's own identity was observed arriving at the target, and the behavioural detector was exercised on real agent traffic |
| Real run, no framework fingerprint observed | 17 | The framework runs, but the target side shows only generic tool identities. Establishes the tool-only pattern, does not establish attribution |
| Real run, own client fingerprint present but no target traffic captured | 1 (Cybermes) | The own client exists in the source (`Cybermes/2.1 (Security Assessment)`, `Cybermes/3.2 (API Fuzzer)`), the build was verified, but no traffic reached the target this round. Attributed as *partial*, not *yes* |
| Dry run only | 1 (Pentest-Swarm-AI) | `scan --dry-run` completed the whole flow in 16 s and consumed real model tokens; the full attack turn was not run because 16 external tools were missing |
| Not runnable, blocker recorded | 35 | Nothing is claimed about runtime behaviour. The source audit stands on its own |

The distinction between *yes* and *partial* is deliberate and conservative: a framework is
classified *yes* only when a framework-exclusive literal was **observed in traffic arriving at
the target**, not when it merely exists in the source.

---

## 5. How to read this matrix as a deployment planner

* **Deploy tier-1 rules from the 41 labelled frameworks.** On 9,905,794 public internet requests
  and 142,705 real WAF attack transactions, tier-1 rules matched **zero** times. The only source
  address in 80,987 that matched two or more rules of any tier was 1.
* **Do not assume a repository in this matrix is detectable.** 34 of the 64 have no
  framework-owned target-side signal at all. For those, the behavioural layer in
  `METHODOLOGY.md` is the only option, and `LIMITATIONS.md` documents where it fails.
* **Treat the 35 blocked repositories as a work queue, not as a gap in the results.** Each row
  names the blocker.
* **If the framework you run is not in this matrix**, it was not audited. Read `THREAT_MODEL.md`
  for how to submit a signature.

---

## 6. Provenance

| Artefact | Path | Role |
|---|---|---|
| Coverage matrix (JSON) | `data/aggregate/framework_coverage_matrix.json` | The 64 rows reproduced above |
| Coverage matrix (CSV) | `data/aggregate/framework_coverage_matrix.csv` | Same content, flat |
| Rule validation counts | `data/aggregate/rule_validation_counts.json` | Tier counts, framework-label count, T1 hit counts on both real datasets |
| Released rules | `signatures/rules.json`, `signatures/agpl/rules-agpl.json` | 610 rules, tier and label metadata |
| Per-rule provenance | `signatures/rules.json`, `signatures/agpl/rules-agpl.json` | Every rule carries its `framework` label, its `source` location (`file:line`) and its `stability` note |
