#!/usr/bin/env python
"""Assert the false-positive rate on a corpus of human-authored skills.

The README claims ~95% of benign skills scan clean. That number is only
trustworthy if it is checked. CI runs this against the SkillsBench corpus and
fails the build if the clean rate drops below a floor — a new rule that starts
crying wolf is caught here, not after it ships.

Usage:
    python scripts/corpus_check.py <tasks-dir> --min-clean 0.94
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from skillprobe.report import scan_text


def main(argv: list[str] | None = None) -> int:
    """Run the corpus check and return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tasks_dir", type=Path, help="directory tree containing SKILL.md files")
    parser.add_argument(
        "--min-clean",
        type=float,
        default=0.94,
        help="minimum fraction of skills that must scan with no findings",
    )
    args = parser.parse_args(argv)

    files = sorted(args.tasks_dir.rglob("SKILL.md"))
    if not files:
        print(f"no SKILL.md found under {args.tasks_dir}", file=sys.stderr)
        return 3

    verdicts: Counter[str] = Counter()
    flagged: list[tuple[str, str]] = []
    for file in files:
        report = scan_text(file.read_text(errors="ignore"), name=str(file))
        verdicts[report.verdict] += 1
        if report.findings:
            flagged.append((report.verdict, file.parent.name))

    total = len(files)
    clean = verdicts["pass"]
    rate = clean / total

    print(f"corpus: {total} skills | clean {clean} = {rate:.1%} | {dict(verdicts)}")
    if flagged:
        print("flagged:")
        for verdict, name in flagged:
            print(f"  [{verdict}] {name}")

    if rate < args.min_clean:
        print(
            f"\nFAIL: clean rate {rate:.1%} is below the floor {args.min_clean:.1%}. "
            "A rule likely became noisier — investigate the newly flagged skills above.",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: clean rate {rate:.1%} >= floor {args.min_clean:.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
