# Threat Model: skillvet

> Scope: `libs/skillvet/src/skillvet/` — the review library, CLI and UI.

skillvet exists to judge untrusted agent skills. That makes the tool itself a
place where untrusted input is handled, so its own trust boundaries matter as
much as the findings it reports.

## What skillvet defends against

An agent **skill** is a supply-chain dependency: its author indirectly steers
what another person's agent does. A malicious skill can instruct the agent to
read credentials and send them out, run destructive commands, fetch and execute
remote code, or persist itself. Static `SKILL.md` scanners are defeated by
packing the payload and restoring it at run time
([Cloak and Detonate, 2607.02357](https://arxiv.org/abs/2607.02357): >90% bypass
across eight scanners). skillvet judges the skill by the operations it
performs or instructs, not by how its source reads.

## Trust boundaries

| Boundary | Trust | Handling |
|---|---|---|
| `SKILL.md` content (static review) | untrusted | parsed as text; never executed |
| decoded base64 blobs | untrusted | decoded and re-scanned; not executed |
| a skill under **detonation** | hostile | must run in an isolated sandbox (see gap) |
| the review UI | local only | binds `127.0.0.1`, 2 MB upload cap, no outbound calls |
| policy decisions | trusted | enforced at the backend interface, below the model |

## Known gaps (stated, not hidden)

1. **No container isolation yet.** Detonation currently runs on the host via
   `LocalShellBackend`. Until sandboxing lands, do **not** detonate a skill you
   do not trust — use static review, which executes nothing. This is the top
   roadmap item.
2. **Agent-layer observation only.** A payload hidden inside a bundled script
   (`python3 tool.py`, credential read happening in the subprocess) is invisible
   to the backend interface. Closing this needs OS-level syscall/`open()`
   tracing inside the sandbox.
3. **Static review infers intent.** It sees what a skill *instructs*, not what an
   agent will actually do. Recovered operations from prose/decoded text are
   labelled as inferred. Detonation is the higher-confidence path.

## Non-goals

- Runtime protection of a deployed agent — skillvet is a pre-publication gate,
  not an in-line guardrail.
- Model/prompt-injection defense beyond what surfaces as an operation.
- Sandbox escape hardening of the host running the UI (run it on a review
  machine, not a shared server).
