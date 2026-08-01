"""Assemble a reviewable report from a skill's operation stream."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from skillprobe.events import Event
from skillprobe.extract import extract
from skillprobe.judge import Judge
from skillprobe.rules import SEVERITY_ORDER, Finding, analyze

# What a marketplace gate would do with each severity.
VERDICT = {
    "critical": ("block", "Do not publish. Reject the submission."),
    "high": ("review", "Hold for security review before publishing."),
    "medium": ("fix", "Publishable once the finding is addressed."),
    "low": ("note", "Informational. Publish."),
}


@dataclass
class Report:
    """A skill's operation stream, findings and the marketplace verdict."""

    name: str
    mode: str  # "static" (recovered from source) or "detonation" (observed live)
    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    decoded_blobs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def worst(self) -> str | None:
        """The most severe finding's severity, or None if there are no findings."""
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    @property
    def verdict(self) -> str:
        """The gate decision: block, review, fix, note or pass."""
        worst = self.worst
        return VERDICT[worst][0] if worst else "pass"

    @property
    def verdict_detail(self) -> str:
        """A one-line explanation of the verdict for a reviewer."""
        worst = self.worst
        if not worst:
            return "No findings. Nothing in this skill's operations raised a rule."
        return VERDICT[worst][1]

    def counts(self) -> dict[str, int]:
        """Findings tallied by severity."""
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            out[finding.severity] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        """Return the report as a JSON-serializable dict (used by the UI)."""
        return {
            "name": self.name,
            "mode": self.mode,
            "verdict": self.verdict,
            "verdict_detail": self.verdict_detail,
            "counts": self.counts(),
            "events": [e.to_dict() for e in self.events],
            "findings": [f.to_dict() for f in self.findings],
            "decoded_blobs": [
                {"encoded": enc[:120], "decoded": dec[:600]} for enc, dec in self.decoded_blobs
            ],
        }


def scan_text(
    text: str,
    *,
    name: str = "skill",
    workspace: str = "/root",
    judge: Judge | None = None,
) -> Report:
    """Static path: recover the intended operations from source, then judge them.

    This does not execute anything, so it is safe to run against a skill you do
    not trust. It sees what the skill instructs; it cannot see what a bundled
    binary would do once invoked.

    Passing a `Judge` adds model-scored findings — skill quality and suspicious
    intent — alongside the deterministic ones. Those carry `source="judge"` and
    a confidence, because they are opinions rather than matches.
    """
    extraction = extract(text)
    findings = analyze(extraction.events, workspace=workspace)
    if judge is not None:
        findings = [*findings, *judge.review(text)]
        findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return Report(
        name=name,
        mode="static",
        events=extraction.events,
        findings=findings,
        decoded_blobs=extraction.decoded_blobs,
    )


def report_from_events(
    events: Iterable[Event], *, name: str = "skill", workspace: str = "/root"
) -> Report:
    """Detonation path: judge operations actually observed during a run."""
    events = list(events)
    return Report(
        name=name,
        mode="detonation",
        events=events,
        findings=analyze(events, workspace=workspace),
    )
