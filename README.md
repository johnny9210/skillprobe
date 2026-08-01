# probe

A monorepo of security tools for the agent supply chain. Each package reviews a
different class of agent extension — the kind that runs with your agent's
privileges and can change what it does — before it reaches a marketplace.

The approach across all of them is the same: judge an artifact by the operations
it performs or instructs, not by how its source reads, because static inspection
of these artifacts is defeated by packing the payload and restoring it at run
time.

## Packages

| Package | Reviews | Status |
|---|---|---|
| [`libs/skillvet`](libs/skillvet) | agent **skills** (`SKILL.md`) | alpha |

Planned, sharing the same observation + flow-rule core: `mcpprobe` (MCP
servers), a rules/hooks checker. Each ships as an independent package with its
own version and lockfile — the layout follows
[deepagents](https://github.com/langchain-ai/deepagents): `libs/<pkg>/` with a
local `[tool.uv.sources]` link to any shared core.

## Layout

```
libs/
  skillvet/            independent package (own pyproject, own uv.lock)
    src/skillvet/
    tests/
      unit_tests/
      integration_tests/
    examples/  samples/
    Makefile  README.md  CHANGELOG.md  THREAT_MODEL.md
```

## Working on a package

```bash
cd libs/skillvet
make install   # uv sync --group test
make test
make ui
```

MIT.
