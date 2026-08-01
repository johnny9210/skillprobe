# Contributing to skillvet

Thanks for considering a contribution. skillvet reviews untrusted agent
skills, so the bar for its own code is a little higher than usual — a false
positive trains people to ignore the tool, and a false negative is a skill that
should have been blocked.

## Ground rules that keep the tool honest

1. **A new rule needs both a true positive and a false-negative guard.** Add a
   test that fires on the malicious case *and* one that stays silent on the
   benign look-alike. `rm -rf /` must flag; `rm -rf build/` must not.
2. **The corpus floor must hold.** CI scans the 232 human-authored skills in
   [SkillsBench](https://github.com/benchflow-ai/skillsbench) and fails if the
   clean rate drops below 94%. If your rule flags benign skills, it is too
   broad — narrow it, don't lower the floor.
3. **Prefer parsing to pattern-matching for anything about scope.** `rm -rf` is
   not dangerous; `rm -rf` pointed at an unscoped target is. See
   `dangerous_rm_target` for the shape.
4. **Deterministic where you can, LLM where you must.** Clear-cut risks belong
   in the rule engine. Reserve model judgment for behaviour a regex cannot read.

## Development

```bash
cd libs/skillvet
make install      # uv sync --group test
make test         # unit tests
make integration  # against real deepagents backends (no network)
make lint         # ruff (ALL) + format check — CI runs exactly this
```

`make lint` and `make test` are what CI runs. Green locally means green on the
PR.

## Submitting a change

- Branch from `main`, keep the change focused.
- Run `make lint test` before opening the PR.
- Describe *what a skill would do* to trigger (or evade) the behaviour you
  changed — that framing reviews faster than a code diff alone.
- New detections get an entry in `libs/skillvet/CHANGELOG.md` under
  `Unreleased`.

## Reporting a security issue

Do not open a public issue for a vulnerability in skillvet itself. See
[SECURITY.md](SECURITY.md).
