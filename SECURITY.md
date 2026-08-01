# Security Policy

skillprobe is a tool for reviewing untrusted agent skills, which means it
handles hostile input by design. Its own trust boundaries are documented in
[libs/skillprobe/THREAT_MODEL.md](libs/skillprobe/THREAT_MODEL.md); please read
that first — several sharp edges are known and stated there, not bugs.

## Reporting a vulnerability

Report privately, not in a public issue:

- Use GitHub's **[Report a vulnerability](https://github.com/johnny9210/skillprobe/security/advisories/new)**
  (Security → Advisories) on this repository, **or**
- email the maintainer listed on the GitHub profile.

Please include a description, affected version or commit, and a minimal
reproduction. We aim to acknowledge within a few days.

## What is in scope

- A malicious skill that produces **no finding** it should have (a false
  negative that lets a real threat through).
- A crafted `SKILL.md` that makes skillprobe itself execute code, exhaust
  resources, or escape its intended read-only static path.
- Any way the review UI leaks data off the local machine.

## What is a known limitation, not a vulnerability

These are documented in the threat model and are not accepted as reports:

- **Detonation runs on the host.** There is no container isolation yet, so you
  must not detonate an untrusted skill. Use static review, which executes
  nothing. This is the top roadmap item.
- **Observation is at the agent layer.** A payload hidden inside a bundled
  script (`python3 tool.py`) is invisible to the backend interface; closing it
  needs OS-level tracing.
- **Static review infers intent.** It reports what a skill instructs, not what
  an agent will certainly do.

## Supported versions

skillprobe is pre-1.0. Only the latest `main` receives fixes.
