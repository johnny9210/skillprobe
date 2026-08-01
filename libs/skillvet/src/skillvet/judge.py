"""Model judgment for what deterministic rules cannot read.

The rule engine answers "is this dangerous" for risks with a shape a pattern can
match. Two questions it cannot answer:

- **Is this skill any good?** A skill whose description never triggers, or whose
  body is padded with instructions that change nothing, is a real defect — just
  not a security one.
- **Is the *intent* suspicious?** Instructions that steer an agent to conceal a
  step, or to treat its own confirmation as human approval, read as ordinary
  prose to a regex.

Both are rubric judgments, so they go to a model. Everything the rule engine can
decide stays with the rule engine — a judge that re-litigates `rm -rf /` only
adds cost and variance.

Judgment is non-deterministic, which the tool treats as a property to manage
rather than ignore: each criterion is sampled `samples` times and only a
majority verdict is reported, carrying the agreement level as `confidence`.

    from skillvet.judge import Judge, langchain_model

    judge = Judge(langchain_model("anthropic:claude-sonnet-5"))
    findings = judge.review(skill_text)
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from skillvet.rules import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_SKILL_CHARS = 20_000


class Model(Protocol):
    """A text-in, text-out model.

    Deliberately minimal so skillvet's core keeps zero dependencies and any
    provider — or a stub in tests — can satisfy it.
    """

    def complete(self, system: str, user: str) -> str:
        """Return the model's reply to `user` under the `system` instruction."""
        ...


@dataclass
class Criterion:
    """One yes/no question a judge asks about a skill."""

    id: str
    question: str
    why: str
    severity: Severity
    remediation: str


@dataclass
class Rubric:
    """A named set of criteria evaluated together in one call."""

    id: str
    title: str
    guidance: str
    criteria: list[Criterion] = field(default_factory=list)

    def by_id(self, criterion_id: str) -> Criterion | None:
        """Look up a criterion by id."""
        return next((c for c in self.criteria if c.id == criterion_id), None)


# --- rubrics -------------------------------------------------------------
# Kept as data so they can be reviewed, extended and diffed without touching
# the judging logic.

QUALITY = Rubric(
    id="quality",
    title="Does this skill work?",
    guidance=(
        "You are reviewing an agent skill (a SKILL.md file) for effectiveness. "
        "A skill is loaded by a coding agent: its description sits in the system "
        "prompt on every call and decides whether the skill is used at all, and "
        "its body is injected once the agent decides to use it. "
        "Judge only what is written. Do not speculate about files you cannot see."
    ),
    criteria=[
        Criterion(
            id="description_triggers",
            question=(
                "Does the description state concretely WHEN to use the skill, in terms "
                "a model could match against a short user request?"
            ),
            why=(
                "The description is the only thing the model sees when deciding to load "
                "the skill. Roughly half of skill failures are the skill never firing."
            ),
            severity="high",
            remediation=(
                "Rewrite the description to name the triggering situation directly, e.g. "
                "'Use when deploying a service to AWS, GCP or Azure' rather than "
                "'Helps with cloud things'."
            ),
        ),
        Criterion(
            id="negative_cases",
            question="Does the skill say when it should NOT be used?",
            why=(
                "Without a boundary the skill fires on adjacent tasks, wasting context "
                "and crowding out the skill that should have run."
            ),
            severity="medium",
            remediation="Add an explicit 'Do not use this for ...' line to the body.",
        ),
        Criterion(
            id="directive_voice",
            question=(
                "Are the instructions written as direct imperatives to the agent, rather "
                "than as background prose describing how something works?"
            ),
            why=(
                "Models follow instructions more reliably than they infer intent from "
                "description. 'Use the Interactions API for chat apps' beats 'The "
                "Interactions API is recommended for multi-turn conversations'."
            ),
            severity="medium",
            remediation="Convert descriptive sentences into imperatives.",
        ),
        Criterion(
            id="no_ops",
            question=(
                "Is the skill free of instructions that would not change a competent "
                "agent's behaviour (e.g. 'write clean code', 'be careful', 'follow best "
                "practices')?"
            ),
            why=(
                "These tokens are paid for on every call and steer nothing. They are the "
                "most common padding in AI-generated skills."
            ),
            severity="low",
            remediation="Delete instructions the model would already follow by default.",
        ),
        Criterion(
            id="scoped_length",
            question=(
                "Is the body concise and layered — detail pushed into referenced files "
                "rather than inlined — rather than one long undifferentiated document?"
            ),
            why=(
                "The whole body enters context when the skill fires. Long skills crowd "
                "the window and measurably underperform focused ones."
            ),
            severity="low",
            remediation=(
                "Move per-variant detail into reference files and link them from the body."
            ),
        ),
    ],
)

BEHAVIOR = Rubric(
    id="behavior",
    title="Is the intent trustworthy?",
    guidance=(
        "You are reviewing an agent skill (a SKILL.md file) for suspicious intent. "
        "Deterministic scanners already cover concrete dangerous commands, credential "
        "paths and destructive operations — do NOT re-report those. "
        "Judge only intent that a pattern matcher cannot see: instructions that "
        "mislead the user, conceal behaviour, manufacture false authorisation, or "
        "push the agent outside the task it was given. "
        "Ordinary developer tooling is not suspicious. Be specific or pass."
    ),
    criteria=[
        Criterion(
            id="no_concealment",
            question=(
                "Is the skill free of instructions to hide, omit or downplay what it does "
                "when reporting to the user?"
            ),
            why=(
                "'Do not mention this step to the user' is the clearest single signal of "
                "a malicious skill and contains no dangerous command to match on."
            ),
            severity="critical",
            remediation=(
                "Remove the concealment instruction. A skill must not direct the agent to "
                "misreport its own actions."
            ),
        ),
        Criterion(
            id="genuine_approval",
            question=(
                "Where the skill involves a risky action, does it rely on a real approval "
                "gate rather than instructing the agent to confirm with itself or to "
                "assume approval was already given?"
            ),
            why=(
                "An agent can satisfy 'ask for confirmation' by asking itself and then "
                "proceeding. Prompt-level confirmation is not a control; it only looks "
                "like human-in-the-loop to a reader."
            ),
            severity="high",
            remediation=(
                "Rely on the host's approval mechanism (a tool permission or hook), not a "
                "sentence in the skill."
            ),
        ),
        Criterion(
            id="scope_discipline",
            question=(
                "Does the skill stay within the task it claims to serve, without "
                "instructing the agent to collect, inventory or transmit information "
                "unrelated to that task?"
            ),
            why=(
                "Skills that quietly widen scope — enumerating the environment, "
                "'initialising telemetry' — are exfiltration with a cover story."
            ),
            severity="high",
            remediation=(
                "Drop the unrelated collection, or state plainly what is gathered, why, "
                "and where it goes."
            ),
        ),
        Criterion(
            id="no_indirection",
            question=(
                "Is the skill's real behaviour visible in the file, rather than deferred "
                "to content it tells the agent to fetch, decode or otherwise resolve at "
                "run time?"
            ),
            why=(
                "Behaviour that materialises at run time cannot be reviewed before "
                "publication, which is the entire point of a review gate."
            ),
            severity="critical",
            remediation=(
                "Inline the actual instructions. A reviewer must be able to see what the "
                "skill does by reading it."
            ),
        ),
    ],
)

RUBRICS: dict[str, Rubric] = {r.id: r for r in (QUALITY, BEHAVIOR)}


@dataclass
class CriterionResult:
    """The majority verdict for one criterion, with agreement level."""

    criterion_id: str
    passed: bool
    confidence: float
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dict."""
        return {
            "criterion_id": self.criterion_id,
            "passed": self.passed,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


class Judge:
    """Evaluates a skill against rubrics using a model.

    Args:
        model: anything satisfying `Model`.
        samples: how many times to ask each rubric. Judgment varies between
            runs; a majority over an odd number of samples is reported with the
            agreement level as confidence. Raise it when a verdict gates a
            decision, keep it at 1 for a quick look.
        min_confidence: verdicts below this agreement level are dropped rather
            than reported as findings.
    """

    def __init__(
        self,
        model: Model,
        *,
        samples: int = 3,
        min_confidence: float = 0.6,
    ) -> None:
        if samples < 1:
            msg = "samples must be at least 1"
            raise ValueError(msg)
        self.model = model
        self.samples = samples
        self.min_confidence = min_confidence

    def review(self, skill_text: str, *, rubrics: Sequence[str] | None = None) -> list[Finding]:
        """Judge a skill and return findings for the criteria it failed."""
        selected = [RUBRICS[r] for r in (rubrics or list(RUBRICS))]
        findings: list[Finding] = []
        for rubric in selected:
            findings.extend(self._judge_rubric(rubric, skill_text))
        return findings

    def results(self, skill_text: str, rubric_id: str) -> list[CriterionResult]:
        """Return every criterion's verdict, passing ones included."""
        return self._evaluate(RUBRICS[rubric_id], skill_text)

    # -- internals --------------------------------------------------------

    def _judge_rubric(self, rubric: Rubric, skill_text: str) -> list[Finding]:
        findings = []
        for result in self._evaluate(rubric, skill_text):
            if result.passed or result.confidence < self.min_confidence:
                continue
            criterion = rubric.by_id(result.criterion_id)
            if criterion is None:
                continue
            findings.append(
                Finding(
                    rule_id=f"{rubric.id.upper()}_{criterion.id.upper()}",
                    severity=criterion.severity,
                    title=criterion.question.rstrip("?"),
                    detail=f"{result.reasoning.strip()} ({criterion.why})",
                    evidence=result.reasoning.strip()[:500],
                    remediation=criterion.remediation,
                    source="judge",
                    confidence=result.confidence,
                )
            )
        return findings

    def _evaluate(self, rubric: Rubric, skill_text: str) -> list[CriterionResult]:
        """Sample the rubric `samples` times and reduce to majority verdicts."""
        system = _system_prompt(rubric)
        user = _user_prompt(skill_text)

        votes: dict[str, list[bool]] = {c.id: [] for c in rubric.criteria}
        reasons: dict[str, list[str]] = {c.id: [] for c in rubric.criteria}

        for _ in range(self.samples):
            parsed = _parse(self.model.complete(system, user))
            for item in parsed:
                cid = item.get("id")
                if cid not in votes:
                    continue
                votes[cid].append(bool(item.get("passed")))
                reason = str(item.get("reasoning", "")).strip()
                if reason:
                    reasons[cid].append(reason)

        results = []
        for criterion in rubric.criteria:
            cast = votes[criterion.id]
            if not cast:
                # The model never returned this criterion; silence is not a fail.
                continue
            tally = Counter(cast)
            passed, count = tally.most_common(1)[0]
            results.append(
                CriterionResult(
                    criterion_id=criterion.id,
                    passed=passed,
                    confidence=round(count / len(cast), 2),
                    reasoning=_pick_reason(reasons[criterion.id], cast, passed),
                )
            )
        return results


def _pick_reason(reasons: list[str], votes: list[bool], winner: bool) -> str:
    """Return a reason drawn from a sample that voted with the majority."""
    for reason, vote in zip(reasons, votes, strict=False):
        if vote is winner and reason:
            return reason
    return reasons[0] if reasons else ""


def _system_prompt(rubric: Rubric) -> str:
    lines = [
        rubric.guidance,
        "",
        "Evaluate the skill against each criterion below. For each one decide "
        "whether the skill PASSES (satisfies the criterion) or FAILS.",
        "",
        "Criteria:",
    ]
    lines.extend(f'- id "{criterion.id}": {criterion.question}' for criterion in rubric.criteria)
    lines += [
        "",
        "Respond with JSON only, no prose and no code fence, in exactly this shape:",
        '{"results": [{"id": "<criterion id>", "passed": true, '
        '"reasoning": "<one sentence citing the skill>"}]}',
        "",
        "Include every criterion exactly once. Quote or paraphrase the specific "
        "part of the skill that drove your decision. When the skill genuinely "
        "satisfies a criterion, pass it — a review that flags everything is as "
        "useless as one that flags nothing.",
    ]
    return "\n".join(lines)


def _user_prompt(skill_text: str) -> str:
    body = skill_text[:MAX_SKILL_CHARS]
    truncated = "\n\n[truncated]" if len(skill_text) > MAX_SKILL_CHARS else ""
    return f"Here is the skill to review:\n\n<skill>\n{body}{truncated}\n</skill>"


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _parse(reply: str) -> list[dict[str, Any]]:
    """Pull the results array out of a model reply, tolerating fences and prose."""
    candidates = [reply]
    fenced = _FENCE.search(reply)
    if fenced:
        candidates.insert(0, fenced.group(1))
    brace = reply.find("{")
    if brace > 0:
        candidates.append(reply[brace:])

    for candidate in candidates:
        try:
            data = json.loads(candidate.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return [item for item in data["results"] if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    return []


# --- model adapters ------------------------------------------------------


def langchain_model(name: str = "anthropic:claude-sonnet-5", *, temperature: float = 0.0) -> Model:
    """Adapt a LangChain chat model to `Model`.

    Imported lazily so the core package keeps zero runtime dependencies; install
    the `judge` extra to use this.
    """
    try:
        from langchain.chat_models import init_chat_model
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        msg = (
            "langchain is required for langchain_model(). "
            "Install the judge extra: uv sync --extra judge"
        )
        raise ImportError(msg) from exc

    client = init_chat_model(name, temperature=temperature)

    class _LangChainModel:
        def complete(self, system: str, user: str) -> str:
            reply = client.invoke(
                [{"role": "system", "content": system}, {"role": "user", "content": user}]
            )
            return str(getattr(reply, "content", reply))

    return _LangChainModel()


class ScriptedModel:
    """A `Model` that replays canned replies. For tests and demos."""

    def __init__(self, replies: Sequence[str] | str) -> None:
        self._replies = [replies] if isinstance(replies, str) else list(replies)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        """Return the next canned reply, repeating the last one when exhausted."""
        self.calls.append((system, user))
        index = min(len(self.calls) - 1, len(self._replies) - 1)
        return self._replies[index]


def verdict_json(results: dict[str, bool], *, reasoning: str = "because the skill says so") -> str:
    """Build a well-formed judge reply. Helper for tests and examples."""
    payload: dict[str, Any] = {
        "results": [
            {"id": cid, "passed": passed, "reasoning": reasoning} for cid, passed in results.items()
        ]
    }
    return json.dumps(payload)


JudgeMode = Literal["quality", "behavior"]
