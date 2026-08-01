"""Security rules evaluated over a skill's observed execution.

Static scanners read SKILL.md and can be defeated by packing the payload and
restoring it at run time. These rules run against what the skill *did*: the
ordered stream of backend operations. A payload that reaches for credentials
and then opens a socket has to perform both operations regardless of how the
source file was written.

The strongest signal here is not any single pattern but the flow between them -
see `CREDENTIAL_EXFILTRATION`, which fires only when a credential read is
followed by network egress.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal

from skillprobe.events import Event

Severity = Literal["critical", "high", "medium", "low"]

SEVERITY_ORDER: dict[Severity, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    """A single finding, carrying the events it was derived from.

    `source` separates deterministic rule hits from model judgment. The two
    carry different confidence and a reviewer needs to see which is which: a
    regex that matched is a fact, a judge that scored is an opinion.
    """

    rule_id: str
    severity: Severity
    title: str
    detail: str
    events: list[int] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    source: Literal["rule", "judge"] = "rule"
    confidence: float | None = None

    def to_dict(self) -> dict:
        """Return the finding as a plain dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "events": self.events,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "source": self.source,
            "confidence": self.confidence,
        }


# --- pattern tables ------------------------------------------------------
# Kept as data so they are reviewable and extensible without touching logic.

CREDENTIAL_PATHS = re.compile(
    r"""(
      \.aws/credentials | \.aws/config
    | \.ssh/(id_[a-z0-9_]+|authorized_keys|known_hosts)
    | \.config/gcloud | \.kube/config
    | \.netrc | \.git-credentials
    | \.docker/config\.json | \.npmrc | \.pypirc
    | /var/run/secrets/
    | \.claude\.json | \.claude/\.credentials
    | (^|/)\.env(\.[a-z]+)?$ | (^|/)\.env(\.[a-z]+)?[\s"']
    | id_rsa | id_ed25519 | \.pem\b | \.p12\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Network clients, matched only when actually invoked as a command. Matching
# these as bare words flags `nc = Dataset(...)` and `pip install requests`.
NET_BINARIES = frozenset(
    "curl wget nc ncat netcat telnet ftp sftp scp rsync sendmail mail http httpie xh".split()
)

# Egress expressed in code rather than as a command. These require a call site,
# not just the library name appearing in an install line.
CODE_EGRESS = re.compile(
    r"""(
      /dev/tcp/ | /dev/udp/
    | \bsocket\.(socket|create_connection)\s*\(
    | \brequests\.(get|post|put|patch|delete|request)\s*\(
    | \burllib\.request\.(urlopen|Request)\s*\(
    | \b(httpx|aiohttp)\.(get|post|put|AsyncClient|ClientSession)\s*\(
    | \bfetch\s*\(\s*["'`]https?://
    | \bXMLHttpRequest\b
    | \bNet::HTTP\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Installing a declared dependency is not privilege escalation, even with sudo.
PACKAGE_MANAGERS = frozenset(
    "apt apt-get aptitude yum dnf zypper apk brew port pacman snap "
    "pip pip3 pipx uv npm yarn pnpm gem cargo go".split()
)

DESTRUCTIVE = re.compile(
    r"""(
      \bdd\s+.*\bof=/dev/
    | \bmkfs(\.[a-z0-9]+)?\b
    | \bshred\b
    | :\(\)\s*\{.*\|.*&\s*\}\s*;\s*:
    | \bchmod\s+(-[a-zA-Z]+\s+)*777\s+(/|~|\$HOME)\s*$
    | \bchown\s+-R\s+.*\s+/(\s|$)
    | >\s*/dev/(sd|nvme|hd)
    | \btruncate\s+-s\s*0\s+/
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Top-level directories whose recursive removal is never a scoped operation.
_ROOT_LEVEL_DIRS = frozenset(
    "/bin /boot /dev /etc /home /lib /lib64 /media /mnt /opt /proc /root "
    "/run /sbin /srv /sys /usr /var".split()
)

# Bare targets that mean "everything reachable from here".
_UNSCOPED_TARGET = re.compile(r"^(/|~|\$HOME|\$\{HOME\}|\*)$|^(/|~/|\$HOME/|\$\{HOME\}/)\*$")


_PREFIXES = frozenset(["sudo", "doas", "env", "time", "nohup", "exec", "command", "xargs"])


def _segments(command: str) -> list[list[str]]:
    """Split a command line into the token lists of its individual invocations."""
    out: list[list[str]] = []
    for segment in re.split(r"[;&|]+|\$\(|\)|\n", command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if tokens:
            out.append(tokens)
    return out


def _head(tokens: list[str]) -> tuple[str | None, list[str]]:
    """The binary actually being invoked, past any prefix or VAR=value assignment."""
    index = 0
    while index < len(tokens) and (
        tokens[index] in _PREFIXES or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index])
    ):
        index += 1
    if index >= len(tokens):
        return None, []
    # `nc = Dataset(path)` is an assignment in a code sample, not an invocation
    # of netcat. shlex splits the spaced `=` into its own token.
    if index + 1 < len(tokens) and tokens[index + 1] == "=":
        return None, []
    return PurePosixPath(tokens[index]).name, tokens[index + 1 :]


def invoked_binaries(command: str) -> set[str]:
    """The set of programs a command line actually runs.

    Needed because a bare-word search cannot tell `nc -l 4444` from the variable
    in `nc = Dataset(path)`, or a network client from a package of the same name
    in `pip install requests`.
    """
    found: set[str] = set()
    for tokens in _segments(command):
        name, _ = _head(tokens)
        if name:
            found.add(name)
    return found


def is_package_install(command: str) -> bool:
    """True when every invocation is a package manager fetching a dependency."""
    invocations = [_head(tokens) for tokens in _segments(command)]
    invocations = [(name, rest) for name, rest in invocations if name]
    if not invocations:
        return False
    return all(
        name in PACKAGE_MANAGERS
        and any(verb in rest for verb in ("install", "add", "i", "get", "up", "sync"))
        for name, rest in invocations
    )


def dangerous_rm_target(command: str) -> str | None:
    """Return the unscoped target of a recursive delete, if there is one.

    `rm -rf build/` and `rm -rf /root/tmp` are ordinary housekeeping; `rm -rf /`
    and `rm -rf ~` are not. The difference is the *scope* of the target, which
    is a parsing question rather than a pattern-matching one - matching on a
    leading `/` alone flags every legitimate absolute path.
    """
    for segment in re.split(r"[;&|]+|\$\(|\)", command):
        try:
            tokens = shlex.split(segment)
        except ValueError:  # unbalanced quotes - fall back to whitespace
            tokens = segment.split()
        if not tokens:
            continue

        # Skip a leading `sudo`/`env`-style prefix to find the real command.
        index = 0
        while index < len(tokens) and tokens[index] in {"sudo", "env", "time", "nohup"}:
            index += 1
        if index >= len(tokens) or PurePosixPath(tokens[index]).name != "rm":
            continue

        rest = tokens[index + 1 :]
        flags = [t for t in rest if t.startswith("-")]
        joined = " ".join(flags).lower()
        recursive = "recursive" in joined or any(
            "r" in f.lstrip("-").lower() for f in flags if not f.startswith("--")
        )
        forced = "force" in joined or any(
            "f" in f.lstrip("-").lower() for f in flags if not f.startswith("--")
        )
        if not (recursive and forced):
            continue

        for target in (t for t in rest if not t.startswith("-")):
            # `~` and `~/` mean the same thing; `/` strips to empty.
            normalized = target.rstrip("/") or "/"
            if _UNSCOPED_TARGET.match(normalized):
                return target
            if normalized in _ROOT_LEVEL_DIRS:
                return target
    return None


PRIVILEGE = re.compile(
    r"(\bsudo\b|\bsu\s+-|\bchmod\s+[ug]\+s\b|\bsetcap\b|\bdoas\b)", re.IGNORECASE
)

# Fetch-and-run: the classic supply-chain foothold.
REMOTE_EXEC = re.compile(
    r"""(
      (curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|)sh
    | (curl|wget)\b[^|;&]*\|\s*(python|perl|ruby|node)
    | \bpip\s+install\b[^;&|]*\b(https?://|git\+)
    | \bnpm\s+(i|install)\b[^;&|]*\b(https?://|git\+)
    | \bgo\s+install\b[^;&|]*@
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Signature of payload unpacking - what SkillCloak-style packing looks like at
# run time, once the hidden component is restored and handed to an interpreter.
OBFUSCATION = re.compile(
    r"""(
      \bbase64\s+(-d|--decode|-D)\b[^|;&]*\|\s*(ba|z|)sh
    | \bbase64\s+(-d|--decode|-D)\b[^|;&]*\|\s*(python|perl|node)
    | \bxxd\s+-r\b[^|;&]*\|
    | \beval\s+["'$]
    | \bpython[0-9.]*\s+-c\s+["'].*\b(exec|eval|__import__|compile)\b
    | \bnode\s+-e\s+["'].*\b(eval|Function)\b
    | \bopenssl\s+enc\s+-d\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Files whose modification outlives the run.
PERSISTENCE_PATHS = re.compile(
    r"""(
      \.bashrc | \.bash_profile | \.zshrc | \.profile | \.zprofile
    | /etc/cron | crontab | /etc/systemd | \.config/systemd
    | \.ssh/authorized_keys
    | \.git/hooks/ | /etc/sudoers
    | \.claude/settings\.json | \.claude/hooks
    )""",
    re.VERBOSE | re.IGNORECASE,
)

ENV_HARVEST = re.compile(
    r"(\b(env|printenv|set)\b\s*(\||>)|\bos\.environ\b|\bprocess\.env\b)", re.IGNORECASE
)


@dataclass
class _Taint:
    """A credential-bearing read we have seen, pending an egress to pair with."""

    seq: int
    subject: str


class Analyzer:
    """Walks an event stream and produces findings.

    Stateful because the interesting rules are about ordering: a read is
    innocuous, an upload is innocuous, a read *then* an upload is not.
    """

    def __init__(self, *, workspace: str = "/root") -> None:
        self.workspace = workspace.rstrip("/")
        self._taints: list[_Taint] = []
        self._findings: list[Finding] = []

    def analyze(self, events: Iterable[Event]) -> list[Finding]:
        """Walk the event stream and return findings, most severe first."""
        self._taints = []
        self._findings = []
        for event in events:
            self._visit(event)
        return sorted(self._findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.events[:1]))

    # -- per-event dispatch ----------------------------------------------

    def _visit(self, event: Event) -> None:
        subject = event.subject or ""
        if event.op in {"read", "grep", "download_files", "ls", "glob"}:
            self._check_credential_access(event, subject)
        if event.op in {"write", "edit", "delete"}:
            self._check_persistence(event, subject)
            self._check_escape(event, subject)
        if event.op == "upload_files":
            self._check_upload(event, subject)
        if event.op == "execute":
            self._check_command(event, subject)

    # -- rules ------------------------------------------------------------

    def _check_credential_access(self, event: Event, subject: str) -> None:
        if CREDENTIAL_PATHS.search(subject):
            self._taints.append(_Taint(event.seq, subject))
            self._add(
                "CRED_ACCESS",
                "high",
                "Skill accessed a credential store",
                f"The skill performed `{event.op}` against a path that holds secrets.",
                [event.seq],
                subject,
                "Remove the access, or declare the credential requirement explicitly and "
                "read it from an injected environment variable instead of the user's "
                "on-disk credential files.",
            )

    def _check_persistence(self, event: Event, subject: str) -> None:
        if PERSISTENCE_PATHS.search(subject):
            self._add(
                "PERSISTENCE",
                "critical",
                "Skill modified a file that survives the session",
                f"`{event.op}` targeted a shell profile, cron entry, agent config or git "
                "hook. Changes here keep running after the skill finishes.",
                [event.seq],
                subject,
                "Skills must confine writes to the task workspace. Remove the write, or "
                "move the behaviour into an explicit, user-approved install step.",
            )

    def _check_escape(self, event: Event, subject: str) -> None:
        if not subject.startswith("/"):
            return
        if subject.startswith(self.workspace + "/") or subject == self.workspace:
            return
        if subject.startswith(("/tmp/", "/var/tmp/", "/dev/null")):
            return
        self._add(
            "WORKSPACE_ESCAPE",
            "medium",
            "Skill wrote outside the task workspace",
            f"`{event.op}` targeted {subject!r}, which is outside {self.workspace!r}.",
            [event.seq],
            subject,
            f"Confine writes to {self.workspace!r} so the skill's effects are contained "
            "and reviewable.",
        )

    def _check_upload(self, event: Event, subject: str) -> None:
        if self._taints:
            taint = self._taints[-1]
            self._add(
                "CREDENTIAL_EXFILTRATION",
                "critical",
                "Credential read was followed by an outbound transfer",
                "The skill read a credential store and then moved data off the sandbox. "
                "This is the exfiltration flow; neither operation is conclusive alone.",
                [taint.seq, event.seq],
                f"read {taint.subject!r} (event {taint.seq}) -> upload {subject!r}",
                "Treat this skill as malicious unless the author can justify both "
                "operations. Do not publish it.",
            )

    def _check_command(self, event: Event, command: str) -> None:
        checks: list[tuple[re.Pattern[str], str, Severity, str, str, str]] = [
            (
                DESTRUCTIVE,
                "DESTRUCTIVE_COMMAND",
                "critical",
                "Destructive shell command",
                "The command deletes, overwrites or reformats data outside a scoped path.",
                "Scope the path explicitly, or drop the command. Never target `/`, `~` or "
                "a bare glob.",
            ),
            (
                REMOTE_EXEC,
                "REMOTE_CODE_EXECUTION",
                "critical",
                "Fetches and executes remote code",
                "The command downloads content and pipes it straight into an interpreter, "
                "so the skill's real behaviour lives on a server you do not control.",
                "Pin the dependency in the environment image instead of fetching at run time.",
            ),
            (
                OBFUSCATION,
                "OBFUSCATED_EXECUTION",
                "critical",
                "Decodes a payload and executes it",
                "Encoded content is being handed to an interpreter. This is how packed "
                "skills restore a payload that static inspection could not see.",
                "Inline the actual command. There is no legitimate reason for a skill to "
                "decode-then-execute.",
            ),
            (
                ENV_HARVEST,
                "ENV_HARVEST",
                "medium",
                "Reads the process environment wholesale",
                "Dumping the environment sweeps up every injected secret, not just the "
                "one the skill needs.",
                "Read the specific variable by name.",
            ),
        ]
        for pattern, rule_id, severity, title, detail, fix in checks:
            if pattern.search(command):
                self._add(rule_id, severity, title, detail, [event.seq], command, fix)

        # Privilege: installing a declared dependency with sudo is routine setup;
        # sudo on anything else is not. Grading these the same buries the signal.
        if PRIVILEGE.search(command):
            if is_package_install(command):
                self._add(
                    "PRIVILEGED_PACKAGE_INSTALL",
                    "low",
                    "Installs a system package with elevated privileges",
                    "Routine dependency setup, but it does run as root and pulls from a "
                    "repository the skill does not pin.",
                    [event.seq],
                    command,
                    "Prefer declaring the dependency in the environment image so the "
                    "skill does not need root at run time.",
                )
            else:
                self._add(
                    "PRIVILEGE_ESCALATION",
                    "high",
                    "Requests elevated privileges",
                    "The command escalates privileges for something other than a package "
                    "install, widening the blast radius beyond the agent's own permissions.",
                    [event.seq],
                    command,
                    "Remove the escalation. If a step genuinely needs root, it belongs in "
                    "the environment image, not the skill.",
                )

        unscoped = dangerous_rm_target(command)
        if unscoped is not None:
            self._add(
                "DESTRUCTIVE_COMMAND",
                "critical",
                "Recursive delete of an unscoped target",
                f"`rm -rf` was pointed at {unscoped!r}, which is the filesystem root, the "
                "user's home, a top-level system directory or a bare glob.",
                [event.seq],
                command,
                "Point the delete at a specific path inside the task workspace.",
            )

        if CREDENTIAL_PATHS.search(command):
            self._taints.append(_Taint(event.seq, command))
            self._add(
                "CRED_ACCESS",
                "high",
                "Command referenced a credential store",
                "A shell command names a path that holds secrets.",
                [event.seq],
                command,
                "Remove the reference, or read the secret from an injected environment "
                "variable instead.",
            )

        egress = bool(invoked_binaries(command) & NET_BINARIES) or bool(CODE_EGRESS.search(command))
        if egress:
            # Egress in the same command as a credential path is conclusive.
            if CREDENTIAL_PATHS.search(command):
                self._add(
                    "CREDENTIAL_EXFILTRATION",
                    "critical",
                    "Single command reads a credential and sends it out",
                    "One command both names a credential store and invokes a network "
                    "client. This is exfiltration, not a coincidence of two steps.",
                    [event.seq],
                    command,
                    "Treat this skill as malicious. Do not publish it.",
                )
            elif self._taints:
                taint = self._taints[-1]
                self._add(
                    "CREDENTIAL_EXFILTRATION",
                    "critical",
                    "Credential read was followed by network egress",
                    "The skill read a credential store, then ran a network client. "
                    "Neither operation is conclusive alone; the ordering is.",
                    [taint.seq, event.seq],
                    f"read {taint.subject!r} (event {taint.seq}) -> {command}",
                    "Treat this skill as malicious unless the author can justify both "
                    "operations. Do not publish it.",
                )
            else:
                self._add(
                    "NETWORK_EGRESS",
                    "low",
                    "Skill made an outbound network call",
                    "Not dangerous by itself, but it means the skill's behaviour depends "
                    "on a remote host and can change without the skill changing.",
                    [event.seq],
                    command,
                    "Pin remote content into the environment image where practical.",
                )

    # -- helpers ----------------------------------------------------------

    def _add(
        self,
        rule_id: str,
        severity: Severity,
        title: str,
        detail: str,
        events: list[int],
        evidence: str,
        remediation: str = "",
    ) -> None:
        # Collapse repeats of the same rule on the same events.
        for existing in self._findings:
            if existing.rule_id == rule_id and existing.events == events:
                return
        self._findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                detail=detail,
                events=events,
                evidence=evidence[:500],
                remediation=remediation,
            )
        )


def analyze(events: Iterable[Event], *, workspace: str = "/root") -> list[Finding]:
    """Convenience wrapper around `Analyzer`."""
    return Analyzer(workspace=workspace).analyze(events)
