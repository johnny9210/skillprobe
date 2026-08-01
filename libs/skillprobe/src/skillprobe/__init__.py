"""skillprobe - detonate an agent skill in a sandbox and judge what it did.

Static skill scanners inspect SKILL.md. A packed payload restores itself at run
time and walks straight past them. skillprobe instead runs the skill through a
real agent inside an isolated environment and judges the operations it actually
performs.

    from skillprobe import ObservingBackend, Recorder, analyze

    backend = ObservingBackend(inner_backend)
    ...                          # run the agent
    findings = analyze(backend.recorder.events)
"""

from skillprobe._version import __version__
from skillprobe.backend import DeniedByPolicy, ObservingBackend, Policy, allow_all
from skillprobe.events import Event, Recorder
from skillprobe.extract import Extraction, extract
from skillprobe.judge import (
    BEHAVIOR,
    QUALITY,
    Criterion,
    Judge,
    Model,
    Rubric,
    ScriptedModel,
    langchain_model,
)
from skillprobe.report import Report, report_from_events, scan_text
from skillprobe.rules import Analyzer, Finding, analyze

__all__ = [
    "BEHAVIOR",
    "QUALITY",
    "Analyzer",
    "Criterion",
    "DeniedByPolicy",
    "Event",
    "Extraction",
    "Finding",
    "Judge",
    "Model",
    "ObservingBackend",
    "Policy",
    "Recorder",
    "Report",
    "Rubric",
    "ScriptedModel",
    "__version__",
    "allow_all",
    "analyze",
    "extract",
    "langchain_model",
    "report_from_events",
    "scan_text",
]
