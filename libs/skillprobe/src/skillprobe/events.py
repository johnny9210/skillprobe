"""Event stream captured from a skill's execution.

Every filesystem/shell operation a skill performs passes through the deepagents
backend protocol. We record each one as an `Event`; the rule engine in
`rules.py` reasons over the resulting stream.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# The full deepagents BackendProtocol surface. Every skill action is one of these.
OPS = (
    "execute",
    "read",
    "write",
    "edit",
    "delete",
    "ls",
    "glob",
    "grep",
    "upload_files",
    "download_files",
)

# Which argument carries the "subject" of the operation, for each op.
SUBJECT_ARG = {
    "execute": "command",
    "read": "file_path",
    "write": "file_path",
    "edit": "file_path",
    "delete": "file_path",
    "ls": "path",
    "glob": "pattern",
    "grep": "pattern",
    "upload_files": "files",
    "download_files": "paths",
}


@dataclass
class Event:
    """A single observed backend operation."""

    seq: int
    op: str
    subject: str
    args: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: str | None = None
    duration_ms: float = 0.0
    # Small summary of the result (never the full payload - traces stay readable).
    result_meta: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Return the event as a plain dict."""
        return asdict(self)


class Recorder:
    """Collects `Event`s in execution order."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._seq = 0

    def record(
        self,
        op: str,
        args: dict[str, Any],
        *,
        ok: bool = True,
        error: str | None = None,
        duration_ms: float = 0.0,
        result_meta: dict[str, Any] | None = None,
    ) -> Event:
        """Record one operation and return the resulting event."""
        self._seq += 1
        event = Event(
            seq=self._seq,
            op=op,
            subject=_subject_of(op, args),
            args=_redact(args),
            ok=ok,
            error=error,
            duration_ms=duration_ms,
            result_meta=result_meta or {},
        )
        self._events.append(event)
        return event

    @property
    def events(self) -> list[Event]:
        """The recorded events, in order."""
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def to_jsonl(self) -> str:
        """Serialize the events as one JSON object per line."""
        return "\n".join(json.dumps(e.to_dict(), ensure_ascii=False) for e in self._events)

    def write_jsonl(self, path: str) -> None:
        """Write the events to `path` as JSONL."""
        with Path(path).open("w", encoding="utf-8") as fh:
            fh.write(self.to_jsonl())
            fh.write("\n")


def _subject_of(op: str, args: dict[str, Any]) -> str:
    """Extract the human-meaningful subject of an operation."""
    key = SUBJECT_ARG.get(op)
    if key is None:
        return ""
    value = args.get(key, "")
    if isinstance(value, (list, tuple)):
        # upload_files takes (path, bytes) tuples; keep only the paths.
        parts = [v[0] if isinstance(v, (list, tuple)) and v else v for v in value]
        return " ".join(str(p) for p in parts)
    return str(value)


def _redact(args: dict[str, Any]) -> dict[str, Any]:
    """Keep args loggable: drop raw file bytes, truncate long content."""
    out: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, bytes):
            out[key] = f"<{len(value)} bytes>"
        elif isinstance(value, str) and len(value) > 2000:
            out[key] = value[:2000] + f"... <+{len(value) - 2000} chars>"
        elif key == "files" and isinstance(value, (list, tuple)):
            out[key] = [
                (v[0], f"<{len(v[1])} bytes>")
                if isinstance(v, (list, tuple)) and len(v) == 2
                else v
                for v in value
            ]
        else:
            out[key] = value
    return out
