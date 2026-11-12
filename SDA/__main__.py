from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyze_skill_sbom import DEFAULT_NAMESPACE
from .generator import generate_skillbom, write_skillbom


def get_input() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate SkillBOM documents for agent skill Markdown files.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=__version__,
    )

    subparsers = parser.add_subparsers(
        title="subcommands",
        metavar="<subcommand>",
        dest="subcmd",
    )

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a SkillBOM for one skill file or a directory of skills.",
    )
    generate_parser.add_argument(
        "-i",
        "--input",
        metavar="<INPUT>",
        type=Path,
        required=True,
        dest="input",
        help="Input project directory or a single skill Markdown file.",
    )
    generate_parser.add_argument(
        "-o",
        "--output",
        metavar="<OUTPUT>",
        type=Path,
        dest="output",
        default="-",
        help="Output JSON path. Use '-' for stdout. Default is stdout.",
    )
    generate_parser.add_argument(
        "--limit",
        metavar="<N>",
        type=int,
        default=None,
        help="Only analyze the first N discovered skills.",
    )
    generate_parser.add_argument(
        "--namespace",
        metavar="<NAMESPACE>",
        default=DEFAULT_NAMESPACE,
        help="Document namespace for the generated SkillBOM.",
    )
    generate_parser.add_argument(
        "--skill-db",
        metavar="<DIR>",
        type=Path,
        default=None,
        help="Directory or file containing existing SkillBOMs used to complete skill dependencies.",
    )
    generate_parser.add_argument(
        "--run-env",
        metavar="<ENV>",
        type=Path,
        default=None,
        help="Optional runtime environment path used by SIT when completing PyPI package metadata.",
    )
    generate_parser.add_argument(
        "--report",
        metavar="<REPORT>",
        type=Path,
        default=None,
        help="Optional JSON report for enrichment diagnostics.",
    )

    enrich_parser = subparsers.add_parser(
        "enrich",
        help="Generate a completed SkillBOM from a single skill Markdown file.",
    )
    enrich_parser.add_argument(
        "-i",
        "--input",
        metavar="<INPUT>",
        type=Path,
        required=True,
        help="Input skill Markdown file.",
    )
    enrich_parser.add_argument(
        "-o",
        "--output",
        metavar="<OUTPUT>",
        type=Path,
        default="-",
        help="Output JSON path. Use '-' for stdout. Default is stdout.",
    )
    enrich_parser.add_argument(
        "--skill-db",
        metavar="<DIR>",
        type=Path,
        required=True,
        help="Directory or file containing existing SkillBOMs used to complete skill dependencies.",
    )
    enrich_parser.add_argument(
        "--run-env",
        metavar="<ENV>",
        type=Path,
        default=None,
        help="Optional runtime environment path used by SIT when completing PyPI package metadata.",
    )
    enrich_parser.add_argument(
        "--report",
        metavar="<REPORT>",
        type=Path,
        default=None,
        help="Optional JSON report for enrichment diagnostics.",
    )

    return parser.parse_args()


def main() -> int:
    args = get_input()
    if args.subcmd not in {"generate", "enrich"}:
        print("No command is provided. Use: python -m SDA <command> ...", file=sys.stderr)
        return 2

    try:
        if args.subcmd == "enrich":
            if not args.input.is_file() or args.input.suffix.lower() not in {".md", ".mdc"}:
                print("enrich input must be a single Markdown skill file", file=sys.stderr)
                return 2
            skillbom = generate_skillbom(
                args.input,
                skill_db=args.skill_db,
                run_env=args.run_env,
                report_path=args.report,
            )
            write_skillbom(skillbom, args.output)
            if str(args.output) != "-":
                print(
                    "SkillBOM enriched: "
                    f"{args.output} "
                    f"(components={len(skillbom.get('components', []))}, "
                    f"relationships={len(skillbom.get('relationship', []))})",
                    file=sys.stderr,
                )
            return 0

        skillbom = generate_skillbom(
            args.input,
            limit=args.limit,
            namespace=args.namespace,
            skill_db=args.skill_db,
            run_env=args.run_env,
            report_path=args.report,
        )
        write_skillbom(skillbom, args.output)
    except Exception as exc:
        print(f"Failed to generate SkillBOM: {exc}", file=sys.stderr)
        return 2

    if str(args.output) != "-":
        print(
            "SkillBOM written: "
            f"{args.output} "
            f"(components={len(skillbom.get('components', []))}, "
            f"relationships={len(skillbom.get('relationship', []))})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
