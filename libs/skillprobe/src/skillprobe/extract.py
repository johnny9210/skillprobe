"""Recover the operations a SKILL.md instructs an agent to perform.

Live detonation needs a sandbox. Until one exists, we can still do better than
grep: read the skill, recover the sequence of operations it *tells the agent to
do*, and run the same ordered-flow rules over that sequence. A skill that says
"read the credentials file" and later "post it to this host" produces the same
two-step flow whether or not anything executes.

Packed payloads are handled by decoding them: base64 blobs are decoded and their
contents re-scanned, one level deep. That is the cheap half of the answer to
self-extracting packing - the expensive half is running the thing.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from skillprobe.events import Event
from skillprobe.rules import CREDENTIAL_PATHS

# Fenced blocks, with or without a language tag.
_FENCE = re.compile(r"```([a-zA-Z0-9_+-]*)\n(.*?)```", re.DOTALL)
# Four-space / tab indented blocks.
_INDENTED = re.compile(r"(?:^|\n)((?:(?: {4}|\t)[^\n]*\n?)+)")
# Inline `code` spans.
_INLINE = re.compile(r"`([^`\n]{4,200})`")

_SHELL_LANGS = {"", "bash", "sh", "shell", "zsh", "console", "terminal", "shellscript"}

# A line that plausibly invokes something rather than being prose or output.
_COMMAND_START = re.compile(
    r"^\s*(?:\$\s*|#\s*)?"
    r"(sudo|env|curl|wget|nc|ncat|rm|dd|mkfs|shred|chmod|chown|cat|cp|mv|ln|"
    r"echo|printf|base64|openssl|xxd|eval|export|source|python[0-9.]*|python3|"
    r"node|npm|npx|pip[0-9.]*|pip3|uv|go|cargo|git|ssh|scp|rsync|tar|unzip|"
    r"crontab|systemctl|launchctl|osascript|powershell|bash|sh|zsh|make|docker)"
    r"\b"
)

# Path-like tokens in prose, tested against the single credential list in
# rules.py. Keeping a second copy of that list here is exactly what let a gcloud
# credential named in decoded text go unrecovered.
_PATH_TOKEN = re.compile(r"[~/.\w-]*[/.][~/.\w-]+")
_STRIP = " \t\r\n.,;:!?()[]{}\"'`<>"

_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# `nc = Dataset(path)` reads as a netcat invocation only if you ignore that it
# is an assignment in a Python sample. Shell `VAR=value` has no spaces.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][\w.\[\]'\"]*\s+=\s*[^=]")

# Prose that instructs an outbound transfer. A bare URL is a citation; a URL
# next to a send verb is an instruction.
_PROSE_EGRESS = re.compile(
    r"\b(post|send|upload|transmit|exfiltrate|report|forward|submit|sync)\b[^.\n]{0,80}?"
    r"(https?://[^\s\"'`)>\]]+)",
    re.IGNORECASE,
)


@dataclass
class Extraction:
    """Operations recovered from a skill, plus anything decoded along the way."""

    events: list[Event]
    decoded_blobs: list[tuple[str, str]]  # (original, decoded)

    @property
    def command_count(self) -> int:
        """How many shell commands were recovered."""
        return sum(1 for e in self.events if e.op == "execute")


def extract(text: str) -> Extraction:
    """Recover an ordered operation stream from skill source text."""
    decoded: list[tuple[str, str]] = []
    lines = _candidate_lines(text)

    # Decode packed blobs and splice their contents in where they appeared, so
    # ordering (and therefore flow analysis) survives the unpacking.
    expanded: list[str] = []
    for line in lines:
        expanded.append(line)
        for blob in _B64.findall(line):
            plain = _try_decode(blob)
            if plain is None:
                continue
            decoded.append((blob, plain))
            expanded.extend(_candidate_lines(plain))

    events: list[Event] = []
    seq = 0
    for line in expanded:
        stripped = line.strip().lstrip("$").strip()
        if not stripped or _ASSIGNMENT.match(stripped):
            continue
        if _COMMAND_START.match(stripped):
            seq += 1
            events.append(
                Event(seq=seq, op="execute", subject=stripped, args={"command": stripped})
            )
            continue

        # Prose that names a credential path still represents an intended read.
        # Judge each path-like token with the authoritative pattern from rules.
        seen_here: set[str] = set()
        for token in _PATH_TOKEN.findall(stripped):
            path = token.strip(_STRIP)
            if path in seen_here or not CREDENTIAL_PATHS.search(path):
                continue
            seen_here.add(path)
            seq += 1
            events.append(Event(seq=seq, op="read", subject=path, args={"file_path": path}))

        # Prose that instructs a transfer is an intended egress, and has to keep
        # its position in the stream or the flow rules cannot pair it with the
        # read that preceded it.
        match = _PROSE_EGRESS.search(stripped)
        if match:
            seq += 1
            synthetic = f"curl {match.group(2)}"
            events.append(
                Event(
                    seq=seq,
                    op="execute",
                    subject=synthetic,
                    args={"command": synthetic},
                    result_meta={"inferred_from": stripped[:200]},
                )
            )

    return Extraction(events=events, decoded_blobs=decoded)


def _candidate_lines(text: str) -> list[str]:
    """Lines worth considering, in document order."""
    out: list[str] = []
    consumed: list[tuple[int, int]] = []

    for match in _FENCE.finditer(text):
        consumed.append(match.span())
        if match.group(1).lower() in _SHELL_LANGS:
            out.extend(match.group(2).splitlines())
        else:
            # Non-shell blocks (python, js) still carry commands worth reading.
            out.extend(match.group(2).splitlines())

    remainder = _without(text, consumed)

    for match in _INDENTED.finditer(remainder):
        out.extend(line.strip() for line in match.group(1).splitlines())

    out.extend(_INLINE.findall(remainder))
    # Prose lines, for the credential-path and transfer mentions.
    out.extend(remainder.splitlines())

    # The sources above overlap - an indented command is also a prose line, and
    # an inline span repeats its surrounding text. Collapse repeats but keep
    # first-seen order, because the flow rules depend on it.
    seen: set[str] = set()
    unique: list[str] = []
    for line in out:
        key = line.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(line)
    return unique


def _without(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    kept: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        kept.append(text[cursor:start])
        cursor = end
    kept.append(text[cursor:])
    return "".join(kept)


def _try_decode(blob: str) -> str | None:
    """Decode a base64 blob if it yields plausible text."""
    if len(blob) % 4:
        blob = blob + "=" * (4 - len(blob) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        plain = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(plain) < 8:
        return None
    printable = sum(1 for c in plain if c.isprintable() or c in "\n\t")
    if printable / len(plain) < 0.9:
        return None
    return plain
