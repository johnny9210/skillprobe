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

### Infrastructure
- CI (GitHub Actions): ruff (ALL) + unit/integration tests across Python
  3.11–3.13, plus a corpus check that fails the build if the SkillsBench clean
  rate drops below 94% — the headline number cannot silently rot.
- `scripts/corpus_check.py` runs the same check locally.
