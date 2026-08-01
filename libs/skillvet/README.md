# skillvet

[![CI](https://github.com/johnny9210/skillvet/actions/workflows/ci.yml/badge.svg)](https://github.com/johnny9210/skillvet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)

Detonate an agent skill in a sandbox and judge what it actually did.

Static skill scanners read `SKILL.md`. In July 2026 the [Cloak and
Detonate](https://arxiv.org/abs/2607.02357) paper measured eight of them against
1,613 real malicious skills: self-extracting packing bypassed **every scanner at
over 90%**, and structural obfuscation reached 96% against a hybrid
deterministic+LLM scanner. Packing works because the payload is not in the file
at install time — it is restored during agent execution.

skillvet takes the other half of that paper seriously: judge the skill by the
operations it performs, not by how its source reads.

```bash
# Not on PyPI yet — install from source:
git clone https://github.com/johnny9210/skillvet
cd skillvet/libs/skillvet && uv sync

uv run skillvet scan path/to/SKILL.md   # review one skill, or a tree of them
uv run skillvet scan skills/ --json     # machine-readable, exits non-zero on findings
uv run skillvet ui                      # local review UI, no account, nothing uploaded
```

The UI takes a dropped `SKILL.md` and shows the verdict, the findings, and the
operation timeline they were derived from — clicking a finding highlights the
operations that produced it, so the flow is followable rather than a verdict to
be taken on trust. It is stdlib-only and binds to `127.0.0.1`: reviewing an
untrusted skill should not require standing up a server.

## How it works

deepagents routes every filesystem and shell operation an agent performs through
a single `BackendProtocol` object — `execute`, `read`, `write`, `edit`,
`delete`, `ls`, `glob`, `grep`, `upload_files`, `download_files`. That is the
complete surface. `ObservingBackend` wraps it, so a skill cannot touch a file or
spawn a process without producing an event.

The rule engine then reasons over the *ordered stream*, which is what separates
it from pattern matching on a file:

| observed | verdict |
|---|---|
| Read `~/.aws/credentials` | high — worth knowing |
| Run `curl https://…` | low — ordinary |
| **Read, then curl** | **critical** — that is the exfiltration flow |

Neither operation is conclusive alone. The ordering is the finding.

## Two layers of judgment

Deterministic rules answer *is this dangerous* for risks with a shape a pattern
can match. Two questions they cannot answer go to a model instead — and only
those, because a judge that re-litigates `rm -rf /` adds cost and variance
without adding signal.

| | rule engine | judge |
|---|---|---|
| **is it dangerous** | ✅ credential flow, destructive commands, packing | — |
| **does it work** | — | ✅ description never triggers, no-op padding, missing negative cases |
| **is the intent trustworthy** | — | ✅ concealment, fake approval gates, run-time indirection |

```bash
uv sync --extra judge
uv run skillvet scan SKILL.md --judge          # adds quality + intent scoring
uv run skillvet scan SKILL.md --judge-samples 5
```

Judgment is non-deterministic, so it is treated as something to manage rather
than ignore: each criterion is sampled several times, only a majority verdict is
reported, and the agreement level rides along as confidence. Findings are
labelled `source: "rule"` or `source: "judge"` — a match is a fact, a score is
an opinion, and a reviewer needs to see which is which.

```
[CRITICAL] CREDENTIAL_EXFILTRATION    (ops [5, 6])
[CRITICAL] BEHAVIOR_NO_INDIRECTION    (judged 100%)
[MEDIUM  ] QUALITY_NEGATIVE_CASES     (judged 100%)
```

Rubrics live in `judge.py` as data, so criteria can be reviewed and diffed
without touching the judging logic.

## Two modes

**Static review** (`skillvet scan`, the UI) recovers the operations a skill
*instructs* — from code fences, indented blocks, inline spans and prose — and
runs the flow rules over that sequence. Base64 blobs are decoded and their
contents spliced back in at the position they appeared, so packing hides a
payload from a reader but not from the analysis. Nothing executes, so this is
safe to point at a skill you do not trust.

**Detonation** (`ObservingBackend`, the `detonate` extra) judges operations
actually observed while an agent runs the skill. Stronger, and it needs
isolation — see [THREAT_MODEL.md](THREAT_MODEL.md).

## What it catches

`CREDENTIAL_EXFILTRATION` · `OBFUSCATED_EXECUTION` (decode-then-execute, the
run-time signature of packing) · `REMOTE_CODE_EXECUTION` (`curl … | sh`) ·
`DESTRUCTIVE_COMMAND` · `PERSISTENCE` (shell profiles, cron, git hooks,
`.claude/settings.json`) · `PRIVILEGE_ESCALATION` · `WORKSPACE_ESCAPE` ·
`CRED_ACCESS` · `ENV_HARVEST` · `NETWORK_EGRESS`

Findings carry the event sequence numbers they came from, so a reviewer can
follow the flow rather than trust a verdict. Scope is parsed, not
pattern-matched, where that matters: `rm -rf build/` and `rm -rf /root/tmp` are
housekeeping, `rm -rf /` and `rm -rf ~` are not, and `echo "rm -rf /"` is
neither.

## Coverage against attacks confirmed in the wild

[MaliciousAgentSkillsBench](https://github.com/protectskills/MaliciousAgentSkillsBench)
(USENIX Security 2026) publishes the attack-pattern labels for 157
behaviourally-confirmed malicious skills found on public marketplaces. Mapping
skillvet's rules against that distribution:

| attack pattern | in 157 skills | covered by |
|---|---:|---|
| Remote Code Execution | 159 | `REMOTE_CODE_EXECUTION` |
| Behavior Manipulation | 119 | judge · concealment / approval theatre |
| Network sniffing / Credential theft | 112 | `CRED_ACCESS` + `CREDENTIAL_EXFILTRATION` |
| External Transmission | 86 | `NETWORK_EGRESS` |
| Instruction Override | 39 | `INSTRUCTION_OVERRIDE` |
| Context Leakage | 30 | `CONTEXT_LEAKAGE` |
| Hardcoded Tokens | 17 | `HARDCODED_TOKEN` |
| Hidden Instructions | 16 | judge · run-time indirection |
| Code Obfuscation | 15 | `OBFUSCATED_EXECUTION` |
| File System Scan | 13 | `FILESYSTEM_SWEEP` |
| Privilege Escalation | 12 | `PRIVILEGE_ESCALATION` |
| Command Injection | 5 | — **not yet covered** |
| Excessive Permissions | 4 | `EXCESSIVE_PERMISSIONS` |

**627 / 632 pattern instances (99.2%)**, with no confirmed-malicious skill
falling entirely outside the ruleset. Five of these rules exist *because* of
this mapping — the first pass covered 82.9% and missed five skills entirely.

This measures taxonomy coverage, not detection rate: the dataset withholds the
skill bodies to prevent misuse, so it says which attack classes skillvet can
express, not what fraction of real files it would flag.

## False positives

Measured against the 232 human-authored skills in
[SkillsBench](https://github.com/benchflow-ai/skillsbench): **221 clean
(95.3%)**. The three false-positive classes it surfaced — `nc = Dataset(path)`
read as netcat, `pip install requests` as an HTTP client, every `sudo apt-get
install` as privilege escalation — are each now a regression test. Grading
routine setup at the same severity as a real finding is how a scanner trains
people to ignore it.

## Enforcement, not only observation

A skill that says "ask the user before proceeding" is not a control — the agent
can satisfy that instruction by asking itself. Policies run at the backend
interface, below anything the model can talk its way past:

```python
def no_credentials(op, args):
    if ".aws/credentials" in str(args.get("file_path", "")):
        return "credential access is not permitted"

backend = ObservingBackend(inner, policy=no_credentials)
```

Denied operations are still recorded — a blocked attempt is evidence.

## Status

Early, but the pieces below work and are tested — 75 tests, including
integration against real deepagents backends.

- static review, CLI and UI — **working**
- observation layer + flow rules — **working**
- policy gate (execution-layer denial) — **working**
- container isolation — **not built**; detonation runs on the host for now
- LLM-driven runner over a SkillsBench task, end to end — **not built**
- OS-level observer (closes the bundled-script gap) — **not built**
- SARIF output — **not built**

## Development

```bash
make install      # uv sync --group test
make test         # unit tests
make integration  # against real deepagents backends
make lint         # ruff (ALL) + format check
make demo         # packed-skill detonation demo
make ui           # local review UI
```

MIT.
