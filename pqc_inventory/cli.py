"""CLI entry: pqc-inventory scan <path> --out <dir>."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pqc_inventory import __version__
from pqc_inventory.overrides import (
    VALID_EXPOSURES,
    load_overrides_json,
    parse_cli_override,
)
from pqc_inventory.baseline import apply_baseline, load_baseline, save_baseline
from pqc_inventory.report import (
    build_inventory,
    render_step_summary,
    write_outputs,
    write_step_summary,
)
from pqc_inventory.scanner import scan_directory

RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "safe": 4}
FAIL_ON_CHOICES = ("never", "high", "medium", "low", "info")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-inventory",
        description=(
            "Defensive static scanner: invent crypto libraries/APIs and flag "
            "quantum-vulnerable usage. No attack or migration tooling. "
            "Scope: source code + dependency manifests only. "
            "Does not guess data lifetime or sensitivity."
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

    # --- Cut B: explicit lifetime / exposure overrides ---
    scan_p.add_argument(
        "--set-lifetime",
        action="append",
        default=[],
        metavar="FILE[:LINE]=YEARS",
        help=(
            "Explicit data_lifetime_years override (repeatable). "
            "Example: python_app/crypto_demo.py:10=15. "
            "Unoverridden findings keep lifetime=null (never invented)."
        ),
    )
    scan_p.add_argument(
        "--set-exposure",
        action="append",
        default=[],
        metavar="FILE[:LINE]=CLASS",
        help=(
            "Explicit exposure override (repeatable). "
            f"Classes: {', '.join(sorted(VALID_EXPOSURES))}."
        ),
    )
    scan_p.add_argument(
        "--set-owner",
        action="append",
        default=[],
        metavar="FILE[:LINE]=NAME",
        help="Explicit owner override (repeatable).",
    )
    scan_p.add_argument(
        "--overrides",
        type=str,
        default=None,
        metavar="FILE.json",
        help="JSON file of explicit overrides (see README). Never invents values.",
    )

    # --- Cut A: hash / checksum suppression ---
    scan_p.add_argument(
        "--hash-policy",
        choices=("drop", "downrank", "keep"),
        default="downrank",
        help=(
            "Local hash/checksum noise: drop from findings, downrank "
            "(default), or keep. Does not guess sensitivity."
        ),
    )

    # --- Cut C: fail-on / exit codes ---
    scan_p.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="never",
        help=(
            "Exit 1 if any non-suppressed finding has quantum_risk at this level "
            "or worse. Default: never (always exit 0 on successful scan). "
            "Example for CI: --fail-on high"
        ),
    )
    scan_p.add_argument(
        "--fail-score",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Exit 1 if any non-suppressed finding has priority_score >= N. "
            "Independent of --fail-on; either threshold can trigger exit 1."
        ),
    )

    # --- Baseline / known-findings (qscan-aligned) ---
    scan_p.add_argument(
        "--write-baseline",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "After scan, write a baseline of current findings "
            "(post-merge / post-hash-policy) to PATH. Still writes normal outs."
        ),
    )
    scan_p.add_argument(
        "--write-step-summary",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Append a CI step-summary markdown to PATH "
            "(defaults to $GITHUB_STEP_SUMMARY when that env is set)."
        ),
    )
    scan_p.add_argument(
        "--baseline",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Load baseline fingerprints; matching findings are suppressed for "
            "--fail-on / --fail-score and omitted from the primary report list."
        ),
    )

    sum_p = sub.add_parser(
        "summarize-out",
        help="Write CI step summary from an existing out/inventory.json",
    )
    sum_p.add_argument(
        "out",
        type=str,
        help="Output directory containing inventory.json (or path to inventory.json)",
    )
    sum_p.add_argument(
        "--to",
        type=str,
        default=None,
        metavar="PATH",
        help="Append markdown to PATH (default: $GITHUB_STEP_SUMMARY or stdout)",
    )
    return parser



def evaluate_fail(
    findings: list,
    *,
    fail_on: str = "never",
    fail_score: int | None = None,
) -> tuple[bool, str]:
    """Return (should_fail, reason). Hash- and baseline-suppressed findings are ignored."""
    active = [
        f
        for f in findings
        if not getattr(f, "suppressed", False)
        and not getattr(f, "baseline_suppressed", False)
    ]
    if fail_on != "never":
        threshold = RISK_ORDER[fail_on]
        offenders = [
            f
            for f in active
            if getattr(f, "quantum_risk", "info") != "safe"
            and RISK_ORDER.get(getattr(f, "quantum_risk", "info"), 9) <= threshold
        ]
        if offenders:
            return True, (
                f"--fail-on {fail_on}: {len(offenders)} finding(s) at "
                f"{fail_on}+ risk"
            )
    if fail_score is not None:
        offenders = [
            f for f in active if (getattr(f, "priority_score", 0) or 0) >= fail_score
        ]
        if offenders:
            return True, (
                f"--fail-score {fail_score}: {len(offenders)} finding(s) with "
                f"priority_score >= {fail_score}"
            )
    return False, ""


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        try:
            extra = []
            for raw in args.set_lifetime:
                extra.append(parse_cli_override(raw, field_name="lifetime"))
            for raw in args.set_exposure:
                extra.append(parse_cli_override(raw, field_name="exposure"))
            for raw in args.set_owner:
                extra.append(parse_cli_override(raw, field_name="owner"))
            if args.overrides:
                extra.extend(load_overrides_json(args.overrides))
        except (ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            # JSON decode errors
            if exc.__class__.__name__ == "JSONDecodeError":
                print(f"error: invalid overrides JSON: {exc}", file=sys.stderr)
                return 2
            raise

        try:
            result = scan_directory(
                target,
                merge=not args.no_merge,
                extra_overrides=extra or None,
                hash_policy=args.hash_policy,  # type: ignore[arg-type]
            )
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        baseline_meta = None
        if args.write_baseline:
            try:
                bl = save_baseline(args.write_baseline, result.findings)
            except OSError as exc:
                print(f"error: cannot write baseline: {exc}", file=sys.stderr)
                return 2
            baseline_meta = {
                "written": True,
                "path": str(args.write_baseline),
                "version": bl["version"],
                "fingerprint_count": len(bl["fingerprints"]),
            }
            print(
                f"Wrote baseline: {args.write_baseline} "
                f"({len(bl['fingerprints'])} fingerprint(s))"
            )

        if args.baseline:
            try:
                bl = load_baseline(args.baseline)
            except FileNotFoundError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            new_findings, suppressed = apply_baseline(result.findings, bl)
            applied = {
                "path": str(args.baseline),
                "version": bl["version"],
                "suppressed_count": len(suppressed),
                "new_count": len(new_findings),
            }
            if baseline_meta and baseline_meta.get("written"):
                baseline_meta = {**baseline_meta, **applied}
            else:
                baseline_meta = applied
            print(
                f"Baseline {args.baseline}: "
                f"{len(suppressed)} suppressed, {len(new_findings)} new"
            )

        json_path, md_path, cbom_path, sarif_path = write_outputs(
            result, args.out, baseline=baseline_meta
        )
        counts = result.counts_by_risk()
        raw_n = len(result.raw_findings)
        suppressed_n = sum(1 for f in result.findings if getattr(f, "suppressed", False))
        baseline_suppressed_n = sum(
            1 for f in result.findings if getattr(f, "baseline_suppressed", False)
        )
        print(
            f"Scanned {result.files_scanned} file(s); "
            f"{len(result.findings)} merged finding(s) "
            f"(raw hits: {raw_n}; suppressed: {suppressed_n}"
            + (
                f"; baseline_suppressed: {baseline_suppressed_n}"
                if args.baseline
                else ""
            )
            + ")."
        )
        print(
            f"  high={counts.get('high', 0)} medium={counts.get('medium', 0)} "
            f"low={counts.get('low', 0)} info={counts.get('info', 0)} "
            f"safe={counts.get('safe', 0)}"
        )
        print(f"Wrote: {json_path}")
        print(f"Wrote: {md_path}")
        print(f"Wrote: {cbom_path}")
        print(f"Wrote: {sarif_path}")

        step_path = args.write_step_summary or os.environ.get("GITHUB_STEP_SUMMARY")
        if step_path:
            inv = build_inventory(result, baseline=baseline_meta)
            write_step_summary(inv, step_path)
            print(f"Wrote step summary: {step_path}")

        should_fail, reason = evaluate_fail(
            result.findings, fail_on=args.fail_on, fail_score=args.fail_score
        )
        if should_fail:
            print(f"fail: {reason}", file=sys.stderr)
            return 1
        return 0

    if args.command == "summarize-out":
        out = Path(args.out)
        inv_path = out if out.name.endswith(".json") else out / "inventory.json"
        if not inv_path.is_file():
            print(f"error: missing {inv_path}", file=sys.stderr)
            return 2
        inventory = json.loads(inv_path.read_text(encoding="utf-8"))
        dest = args.to or os.environ.get("GITHUB_STEP_SUMMARY")
        body = render_step_summary(inventory)
        if dest:
            write_step_summary(inventory, dest)
            print(f"Wrote step summary: {dest}")
        else:
            print(body, end="" if body.endswith("\n") else "\n")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
