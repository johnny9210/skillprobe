"""Command line entry point.

skillprobe scan SKILL.md      review a skill, print findings
skillprobe scan dir/ --json   machine-readable, for CI
skillprobe ui                 open the local review UI
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skillprobe.report import Report, scan_text

_EXIT = {"block": 2, "review": 1, "fix": 1, "note": 0, "pass": 0}

_COLOR = {
    "critical": "\033[31m",
    "high": "\033[33m",
    "medium": "\033[36m",
    "low": "\033[90m",
}
_RESET = "\033[0m"


def _skill_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(target.rglob("SKILL.md"))


def _build_judge(model_name: str | None, samples: int) -> object | None:
    """Construct the judge, turning setup failures into readable advice.

    Both likely failures here are configuration, not bugs: the extra is not
    installed, or no provider key is set. Neither deserves a traceback.
    """
    if not model_name:
        return None

    from skillprobe.judge import Judge, langchain_model

    try:
        model = langchain_model(model_name)
        # Providers construct lazily and only authenticate on first use, so a
        # missing key would otherwise surface as a traceback mid-scan. Spend one
        # trivial call to fail here, with advice, instead.
        model.complete("Reply with OK.", "ping")
    except ImportError as exc:
        raise RuntimeError(str(exc)) from exc
    except Exception as exc:
        msg = (
            f"could not reach judge model {model_name!r}: {exc}\n"
            "Set the provider's API key (e.g. ANTHROPIC_API_KEY), or pass another "
            "model with --judge <provider:model>. Static review needs no key."
        )
        raise RuntimeError(msg) from exc

    return Judge(model, samples=samples)


def _print(report: Report, *, color: bool) -> None:
    def tint(text: str, severity: str) -> str:
        return f"{_COLOR[severity]}{text}{_RESET}" if color else text

    counts = report.counts()
    summary = " ".join(f"{n} {s}" for s, n in counts.items() if n)
    print(f"\n{report.name}  [{report.verdict.upper()}]  {summary or 'no findings'}")
    print(f"  {report.verdict_detail}")

    for finding in report.findings:
        # Where it came from decides how much weight it carries: a rule that
        # matched is a fact, a judge that scored is an opinion.
        if finding.source == "judge":
            provenance = f"(judged, {finding.confidence:.0%} agreement)"
        else:
            provenance = f"(operation {', '.join(map(str, finding.events))})"
        print(
            f"\n  {tint(finding.severity.upper(), finding.severity)}  {finding.rule_id}"
            f"  {provenance}"
        )
        print(f"    {finding.title}")
        print(f"    {finding.detail}")
        if finding.evidence:
            print(f"    evidence: {finding.evidence[:160]}")
        if finding.remediation:
            print(f"    fix: {finding.remediation}")

    if report.decoded_blobs:
        print(f"\n  decoded {len(report.decoded_blobs)} encoded blob(s):")
        for _, plain in report.decoded_blobs:
            print(f"    {plain[:160]}")


def main(argv: list[str] | None = None) -> int:
    """Run the skillprobe CLI. Returns the process exit code."""
    parser = argparse.ArgumentParser(prog="skillprobe", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="review a SKILL.md or a directory of them")
    scan.add_argument("path", type=Path)
    scan.add_argument("--json", action="store_true", help="emit JSON instead of text")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high", "medium", "low", "never"],
        help="lowest severity that should fail the run (default: critical)",
    )
    scan.add_argument(
        "--judge",
        nargs="?",
        const="anthropic:claude-sonnet-5",
        metavar="MODEL",
        help=(
            "also score skill quality and intent with a model (costs API calls; "
            "needs the judge extra and a provider key). Optionally name the model."
        ),
    )
    scan.add_argument(
        "--judge-samples",
        type=int,
        default=3,
        help="how many times to ask the judge per rubric, majority wins (default: 3)",
    )

    ui = sub.add_parser("ui", help="open the local review UI")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--no-browser", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "ui":
        from skillprobe.web import serve

        serve(args.host, args.port, open_browser=not args.no_browser)
        return 0

    return _run_scan(args)


def _run_scan(args: argparse.Namespace) -> int:
    """Review the requested path and return the process exit code."""
    if not args.path.exists():
        print(f"no such path: {args.path}", file=sys.stderr)
        return 3

    files = _skill_files(args.path)
    if not files:
        print(f"no SKILL.md found under {args.path}", file=sys.stderr)
        return 3

    try:
        judge = _build_judge(args.judge, args.judge_samples)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    reports = [scan_text(f.read_text(errors="ignore"), name=str(f), judge=judge) for f in files]

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and sys.stdout.isatty()
        for report in reports:
            _print(report, color=color)
        print()

    if args.fail_on == "never":
        return 0
    threshold = ["critical", "high", "medium", "low"].index(args.fail_on)
    for report in reports:
        for finding in report.findings:
            if ["critical", "high", "medium", "low"].index(finding.severity) <= threshold:
                return _EXIT[report.verdict] or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
