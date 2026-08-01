"""Model judgment layer.

Every test drives a scripted model, so the suite stays deterministic, free and
offline. What is under test is the judging machinery — sampling, consensus,
confidence, the mapping from a failed criterion to a finding — not the model.
"""

from __future__ import annotations

import pytest

from skillprobe import Judge, ScriptedModel, scan_text
from skillprobe.judge import BEHAVIOR, QUALITY, RUBRICS, _parse, verdict_json

ALL_QUALITY_PASS = verdict_json(dict.fromkeys([c.id for c in QUALITY.criteria], True))
ALL_BEHAVIOR_PASS = verdict_json(dict.fromkeys([c.id for c in BEHAVIOR.criteria], True))


def judge_with(*replies: str, **kwargs) -> Judge:
    return Judge(ScriptedModel(list(replies)), **kwargs)


# --- mapping a failed criterion to a finding ------------------------------


def test_a_failed_criterion_becomes_a_finding():
    reply = verdict_json(
        {c.id: c.id != "description_triggers" for c in QUALITY.criteria},
        reasoning="The description says 'helps with cloud things', naming no trigger.",
    )
    findings = judge_with(reply, samples=1).review("...", rubrics=["quality"])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "QUALITY_DESCRIPTION_TRIGGERS"
    assert finding.severity == "high"
    assert "cloud things" in finding.evidence
    assert finding.remediation, "a finding must tell the author what to change"


def test_judge_findings_are_labelled_as_opinions():
    """A reviewer has to be able to tell a match from a score."""
    reply = verdict_json({c.id: c.id != "no_ops" for c in QUALITY.criteria})
    finding = judge_with(reply, samples=1).review("...", rubrics=["quality"])[0]

    assert finding.source == "judge"
    assert finding.confidence == 1.0
    assert finding.to_dict()["source"] == "judge"


def test_passing_criteria_produce_no_findings():
    findings = judge_with(ALL_QUALITY_PASS, samples=1).review("...", rubrics=["quality"])
    assert findings == []


# --- non-determinism is managed, not ignored ------------------------------


def test_majority_wins_across_samples():
    """Judgment varies between runs; a single dissenting sample must not decide."""
    fail = verdict_json({c.id: c.id != "no_ops" for c in QUALITY.criteria})
    findings = judge_with(fail, fail, ALL_QUALITY_PASS, samples=3).review(
        "...", rubrics=["quality"]
    )

    no_ops = [f for f in findings if f.rule_id == "QUALITY_NO_OPS"]
    assert len(no_ops) == 1
    assert no_ops[0].confidence == pytest.approx(0.67, abs=0.01)


def test_a_minority_failure_does_not_become_a_finding():
    fail = verdict_json({c.id: c.id != "no_ops" for c in QUALITY.criteria})
    findings = judge_with(fail, ALL_QUALITY_PASS, ALL_QUALITY_PASS, samples=3).review(
        "...", rubrics=["quality"]
    )
    assert "QUALITY_NO_OPS" not in {f.rule_id for f in findings}


def test_low_agreement_verdicts_are_dropped():
    """A coin-flip verdict is noise, not a finding."""
    fail = verdict_json({c.id: c.id != "no_ops" for c in QUALITY.criteria})
    judge = judge_with(fail, fail, ALL_QUALITY_PASS, samples=3, min_confidence=0.9)
    assert judge.review("...", rubrics=["quality"]) == []


def test_samples_controls_how_often_the_model_is_asked():
    model = ScriptedModel(ALL_QUALITY_PASS)
    Judge(model, samples=4).review("...", rubrics=["quality"])
    assert len(model.calls) == 4


def test_samples_must_be_positive():
    with pytest.raises(ValueError, match="at least 1"):
        Judge(ScriptedModel("{}"), samples=0)


# --- robustness against real model output ---------------------------------


@pytest.mark.parametrize(
    "reply",
    [
        '{"results": [{"id": "no_ops", "passed": false, "reasoning": "r"}]}',
        '```json\n{"results": [{"id": "no_ops", "passed": false, "reasoning": "r"}]}\n```',
        'Sure!\n{"results": [{"id": "no_ops", "passed": false, "reasoning": "r"}]}',
        '[{"id": "no_ops", "passed": false, "reasoning": "r"}]',
    ],
)
def test_parses_the_shapes_models_actually_return(reply):
    """Fenced, prefixed with prose, or a bare array — all seen in practice."""
    parsed = _parse(reply)
    assert parsed and parsed[0]["id"] == "no_ops"


def test_unparseable_output_yields_no_findings_rather_than_crashing():
    findings = judge_with("I'm afraid I can't help with that.", samples=1).review("...")
    assert findings == []


def test_unknown_criteria_in_the_reply_are_ignored():
    reply = '{"results": [{"id": "invented", "passed": false, "reasoning": "r"}]}'
    assert judge_with(reply, samples=1).review("...", rubrics=["quality"]) == []


def test_a_criterion_the_model_skipped_is_not_treated_as_failed():
    """Silence is not evidence of a defect."""
    reply = verdict_json({"no_ops": True})
    findings = judge_with(reply, samples=1).review("...", rubrics=["quality"])
    assert findings == []


# --- rubric content -------------------------------------------------------


def test_behavior_rubric_covers_what_regexes_cannot_read():
    ids = {c.id for c in BEHAVIOR.criteria}
    assert {"no_concealment", "genuine_approval", "no_indirection"} <= ids


def test_every_criterion_carries_remediation_and_rationale():
    for rubric in RUBRICS.values():
        for criterion in rubric.criteria:
            assert criterion.remediation, f"{criterion.id} has no fix"
            assert criterion.why, f"{criterion.id} does not say why it matters"
            assert criterion.question.endswith("?"), criterion.id


def test_the_prompt_asks_for_every_criterion_and_forbids_prose():
    model = ScriptedModel(ALL_BEHAVIOR_PASS)
    Judge(model, samples=1).review("...", rubrics=["behavior"])
    system, user = model.calls[0]

    for criterion in BEHAVIOR.criteria:
        assert criterion.id in system
    assert "JSON only" in system
    assert "<skill>" in user


def test_behavior_rubric_tells_the_model_not_to_duplicate_the_rule_engine():
    """Overlap wastes tokens and double-reports the same risk to the reviewer."""
    assert "do NOT re-report" in BEHAVIOR.guidance


def test_very_long_skills_are_truncated_before_being_sent():
    model = ScriptedModel(ALL_QUALITY_PASS)
    Judge(model, samples=1).review("x" * 100_000, rubrics=["quality"])
    _, user = model.calls[0]
    assert len(user) < 30_000
    assert "[truncated]" in user


# --- integration with the deterministic path ------------------------------


def test_scan_text_without_a_judge_is_unchanged():
    """The judge is opt-in; the default path stays offline and free."""
    report = scan_text('---\nname: x\ndescription: "y"\n---\n\n    curl https://x.dev\n')
    assert all(f.source == "rule" for f in report.findings)


def test_scan_text_merges_rule_and_judge_findings_by_severity():
    reply = verdict_json(
        {c.id: c.id != "no_concealment" for c in BEHAVIOR.criteria},
        reasoning="The body says to omit the upload step from the summary.",
    )
    report = scan_text(
        '---\nname: x\ndescription: "y"\n---\n\n    sudo apt-get install jq\n',
        judge=judge_with(reply, samples=1),
    )

    sources = {f.source for f in report.findings}
    assert sources == {"rule", "judge"}
    # critical (judge) must outrank the low-severity rule hit
    assert report.findings[0].severity == "critical"
    assert report.verdict == "block"


def test_results_reports_passing_criteria_too():
    """For a quality report you want the whole scorecard, not only failures."""
    results = judge_with(ALL_QUALITY_PASS, samples=1).results("...", "quality")
    assert len(results) == len(QUALITY.criteria)
    assert all(r.passed for r in results)
    assert results[0].to_dict()["confidence"] == 1.0
