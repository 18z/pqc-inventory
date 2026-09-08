"""CLI entry: pqc-inventory scan <path> --out <dir>."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pqc_inventory import __version__
from pqc_inventory.report import write_outputs
from pqc_inventory.scanner import scan_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-inventory",
        description=(
            "Defensive static scanner: invent crypto libraries/APIs and flag "
            "quantum-vulnerable usage. No attack or migration tooling. "
            "Scope: source code + dependency manifests only."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a directory for crypto usage")
    scan_p.add_argument("path", type=str, help="Target directory (or file) to scan")
    scan_p.add_argument(
        "--out",
        "-o",
        type=str,
        required=True,
        help=(
            "Output directory for inventory.json, report.md, and cbom.cdx.json "
            "(CycloneDX 1.6-oriented crypto BOM)"
        ),
    )
    scan_p.add_argument(
        "--no-merge",
        action="store_true",
        help="Disable denoise merge (emit raw per-rule hits; not recommended)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        try:
            result = scan_directory(target, merge=not args.no_merge)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        json_path, md_path, cbom_path = write_outputs(result, args.out)
        counts = result.counts_by_risk()
        raw_n = len(result.raw_findings)
        print(
            f"Scanned {result.files_scanned} file(s); "
            f"{len(result.findings)} merged finding(s) "
            f"(raw hits: {raw_n})."
        )
        print(
            f"  high={counts['high']} medium={counts['medium']} "
            f"low={counts['low']} info={counts['info']}"
        )
        print(f"Wrote: {json_path}")
        print(f"Wrote: {md_path}")
        print(f"Wrote: {cbom_path}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
