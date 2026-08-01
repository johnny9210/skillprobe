# Changelog

All notable changes to skillprobe are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to adhere
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Observation layer (`ObservingBackend`) wrapping the deepagents backend
  protocol, recording every filesystem and shell operation a skill performs.
- Flow-based rule engine (`Analyzer`) that reasons over the ordered operation
  stream — credential-read-then-egress is critical, either half alone is not.
- Static review (`scan_text`) that recovers intended operations from `SKILL.md`
  source, decoding base64 blobs one level deep and splicing their contents back
  in at position so packing does not hide the flow.
- Execution-layer policy gate: operations can be denied at the backend
  interface, below anything the model can talk its way past.
- CLI (`skillprobe scan`, `skillprobe ui`) and a stdlib-only local review UI.
- Detection of: credential exfiltration, decode-then-execute, fetch-and-run,
  destructive commands (parsed, not pattern-matched), persistence writes,
  privilege escalation, workspace escape, environment harvesting.

### Measured
- 95.3% clean (221/232) against the human-authored SkillsBench corpus; the
  three false-positive classes it surfaced (`nc = Dataset(...)`,
  `pip install requests`, `sudo apt-get install`) are now regression tests.

### Added — model judgment
- `Judge` scores a skill against rubrics for what deterministic rules cannot
  read: whether the skill *works* (description never triggers, no-op padding,
  missing negative cases) and whether its *intent* is trustworthy (concealment,
  prompt-level approval theatre, run-time indirection).
- Non-determinism is managed rather than ignored — each criterion is sampled N
  times, only majority verdicts are reported, and agreement rides along as
  `confidence`. Low-agreement verdicts are dropped.
- Findings carry `source` (`rule` vs `judge`); the CLI and UI show provenance so
  a match is not mistaken for a score.
- `Model` is a two-method protocol, so the core keeps zero runtime dependencies.
  `langchain_model()` adapts any LangChain chat model under the `judge` extra;
  `ScriptedModel` keeps the test suite offline and free.

### Infrastructure
- CI (GitHub Actions): ruff (ALL) + unit/integration tests across Python
  3.11–3.13, plus a corpus check that fails the build if the SkillsBench clean
  rate drops below 94% — the headline number cannot silently rot.
- `scripts/corpus_check.py` runs the same check locally.
