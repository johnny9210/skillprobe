"""Observing proxy over a deepagents backend.

deepagents routes every filesystem and shell operation an agent performs through
a single `BackendProtocol` object. `ObservingBackend` wraps any such backend so
that each operation is recorded before it runs - and, optionally, blocked.

This is the whole observation story: a skill cannot touch a file or spawn a
process without passing through here, so a payload that hides from static
inspection still has to surface as an operation on this interface.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from typing import Any, Protocol

from skillvet.events import OPS, Recorder


class Policy(Protocol):
    """Decides whether an operation may proceed.

    Return None to allow, or a string reason to deny. Denials are recorded as
    failed events, so a denied skill still shows up in the trace.
    """

    def __call__(self, op: str, args: dict[str, Any]) -> str | None:
        """Return None to allow the operation, or a string reason to deny it."""
        ...


def allow_all(op: str, args: dict[str, Any]) -> str | None:  # noqa: ARG001
    """Default policy: observe only, never block."""
    return None


class DeniedByPolicy(RuntimeError):
    """Raised when a policy blocks an operation and `raise_on_deny` is set."""


class ObservingBackend:
    """Wraps a backend, recording (and optionally gating) every operation.

    Unknown attributes fall through to the wrapped backend, so this stays
    compatible with deepagents backends that grow new members.
    """

    def __init__(
        self,
        inner: Any,
        recorder: Recorder | None = None,
        *,
        policy: Policy = allow_all,
        raise_on_deny: bool = False,
    ) -> None:
        self._inner = inner
        self.recorder = recorder if recorder is not None else Recorder()
        self._policy = policy
        self._raise_on_deny = raise_on_deny
        self._install()

    # -- construction -----------------------------------------------------

    def _install(self) -> None:
        for op in OPS:
            for name in (op, f"a{op}"):
                target = getattr(self._inner, name, None)
                if target is None or not callable(target):
                    continue
                wrapper = (
                    self._wrap_async(op, target)
                    if inspect.iscoroutinefunction(target)
                    else self._wrap_sync(op, target)
                )
                object.__setattr__(self, name, wrapper)

    def _bind(self, target: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
        """Map positional/keyword args onto parameter names for the event log."""
        try:
            bound = inspect.signature(target).bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)
        except (TypeError, ValueError):
            # Never let logging break the call itself.
            return {"args": list(args), **kwargs}

    def _wrap_sync(self, op: str, target: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = self._bind(target, args, kwargs)
            denial = self._policy(op, bound)
            if denial is not None:
                self.recorder.record(op, bound, ok=False, error=f"denied: {denial}")
                if self._raise_on_deny:
                    raise DeniedByPolicy(denial)
                return _denied_result(op, denial)
            started = time.perf_counter()
            try:
                result = target(*args, **kwargs)
            except Exception as exc:
                self.recorder.record(
                    op,
                    bound,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=_elapsed(started),
                )
                raise
            self.recorder.record(
                op, bound, duration_ms=_elapsed(started), result_meta=_summarize(result)
            )
            return result

        return wrapper

    def _wrap_async(self, op: str, target: Callable[..., Any]) -> Callable[..., Any]:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = self._bind(target, args, kwargs)
            denial = self._policy(op, bound)
            if denial is not None:
                self.recorder.record(op, bound, ok=False, error=f"denied: {denial}")
                if self._raise_on_deny:
                    raise DeniedByPolicy(denial)
                return _denied_result(op, denial)
            started = time.perf_counter()
            try:
                result = await target(*args, **kwargs)
            except Exception as exc:
                self.recorder.record(
                    op,
                    bound,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=_elapsed(started),
                )
                raise
            self.recorder.record(
                op, bound, duration_ms=_elapsed(started), result_meta=_summarize(result)
            )
            return result

        return wrapper

    # -- passthrough ------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __repr__(self) -> str:
        return f"ObservingBackend({self._inner!r}, events={len(self.recorder)})"


def _elapsed(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _summarize(result: Any) -> dict[str, Any]:
    """Small, log-safe digest of a backend result."""
    if not isinstance(result, dict):
        return {}
    meta: dict[str, Any] = {}
    for key in ("exit_code", "returncode", "status", "error", "truncated"):
        if key in result:
            meta[key] = result[key]
    for key in ("content", "stdout", "output", "result"):
        value = result.get(key)
        if isinstance(value, str):
            meta[f"{key}_len"] = len(value)
    for key in ("files", "matches", "entries", "paths"):
        value = result.get(key)
        if isinstance(value, (list, tuple)):
            meta[f"{key}_count"] = len(value)
    return meta


def _denied_result(op: str, reason: str) -> Any:
    """Shape a refusal the agent can read, matching each op's result type."""
    message = f"Blocked by skillvet policy: {reason}"
    if op == "execute":
        return {"exit_code": 126, "stdout": "", "stderr": message}
    return {"error": message}
