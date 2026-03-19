#!/usr/bin/env python3
"""Run the full retrobios pipeline: generate DB, verify, generate packs.

Steps:
  1. generate_db.py --force     (rebuild database.json from bios/)
  2. refresh_data_dirs.py       (update Dolphin Sys, PPSSPP, etc.)
  3. verify.py --all            (check all platforms)
  4. generate_pack.py --all     (build ZIP packs)
  5. consistency check          (verify counts == pack counts)

Usage:
    python scripts/pipeline.py                    # active platforms
    python scripts/pipeline.py --include-archived # all platforms
    python scripts/pipeline.py --skip-packs       # steps 1-3 only
    python scripts/pipeline.py --offline          # skip step 2
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time


def run(cmd: list[str], label: str) -> tuple[bool, str]:
    """Run a command. Returns (success, captured_output)."""
    print(f"\n--- {label} ---", flush=True)
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
    elapsed = time.monotonic() - start

    output = result.stdout
    if result.stderr:
        output += result.stderr

    ok = result.returncode == 0
    print(output, end="")
    print(f"--- {label}: {'OK' if ok else 'FAILED'} ({elapsed:.1f}s) ---")
    return ok, output


def parse_verify_counts(output: str) -> dict[str, tuple[int, int, int, int]]:
    """Extract per-group OK/total/wrong/missing from verify output.

    Returns {group_label: (ok, total, wrong, missing)}.
    Group label = "Lakka / RetroArch" for grouped platforms.
    """
    counts = {}
    for line in output.splitlines():
        if " files OK" not in line:
            continue
        label, rest = line.split(":", 1)
        rest = rest.strip()
        frac = rest.split(" files OK")[0].strip()
        if "/" not in frac:
            continue
        ok, total = int(frac.split("/")[0]), int(frac.split("/")[1])
        wrong = 0
        missing = 0
        if "wrong hash" in rest:
            for part in rest.split(","):
                part = part.strip()
                if "wrong hash" in part:
                    wrong = int(part.split()[0])
                elif "missing" in part:
                    missing = int(part.split()[0])
        counts[label.strip()] = (ok, total, wrong, missing)
    return counts


def parse_pack_counts(output: str) -> dict[str, tuple[int, int, int, int, int]]:
    """Extract per-pack files_packed/ok/total/wrong/missing.

    Returns {pack_label: (packed, ok, total, wrong, missing)}.
    """
    import re
    counts = {}
    current_label = ""
    for line in output.splitlines():
        m = re.match(r"Generating (?:shared )?pack for (.+)\.\.\.", line)
        if m:
            current_label = m.group(1)
            continue
        if "files packed" not in line or "files OK" not in line:
            continue
        packed = int(re.search(r"(\d+) files packed", line).group(1))
        frac_m = re.search(r"(\d+)/(\d+) files OK", line)
        ok, total = int(frac_m.group(1)), int(frac_m.group(2))
        wrong_m = re.search(r"(\d+) wrong hash", line)
        wrong = int(wrong_m.group(1)) if wrong_m else 0
        miss_m = re.search(r"(\d+) missing", line)
        missing = int(miss_m.group(1)) if miss_m else 0
        counts[current_label] = (packed, ok, total, wrong, missing)
    return counts


def check_consistency(verify_output: str, pack_output: str) -> bool:
    """Verify that check counts match between verify and pack for each platform."""
    v = parse_verify_counts(verify_output)
    p = parse_pack_counts(pack_output)

    print("\n--- 5/5 consistency check ---")
    all_ok = True
    matched_verify = set()

    for v_label, (v_ok, v_total, v_wrong, v_miss) in sorted(v.items()):
        # Match by label overlap (handles "Lakka + RetroArch" vs "Lakka / RetroArch")
        p_match = None
        for p_label in p:
            # Check if any platform name in the verify group matches the pack label
            v_names = {n.strip().lower() for n in v_label.split("/")}
            p_names = {n.strip().lower() for n in p_label.replace("+", "/").split("/")}
            if v_names & p_names:
                p_match = p_label
                break

        if p_match:
            matched_verify.add(v_label)
            _, p_ok, p_total, p_wrong, p_miss = p[p_match]
            checks_match = v_ok == p_ok and v_total == p_total
            detail_match = v_wrong == p_wrong and v_miss == p_miss
            if checks_match and detail_match:
                print(f"  {v_label}: {v_ok}/{v_total} OK")
            else:
                print(f"  {v_label}: MISMATCH")
                print(f"    verify: {v_ok}/{v_total} OK, {v_wrong} wrong, {v_miss} missing")
                print(f"    pack:   {p_ok}/{p_total} OK, {p_wrong} wrong, {p_miss} missing")
                all_ok = False
        else:
            # Grouped platform — check if another label in the same verify group matched
            v_names = [n.strip() for n in v_label.split("/")]
            other_matched = any(
                name in lbl for lbl in matched_verify for name in v_names
            )
            if not other_matched:
                print(f"  {v_label}: {v_ok}/{v_total} OK (no separate pack — grouped or archived)")

    status = "OK" if all_ok else "FAILED"
    print(f"--- consistency check: {status} ---")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Run the full retrobios pipeline")
    parser.add_argument("--include-archived", action="store_true",
                        help="Include archived platforms")
    parser.add_argument("--skip-packs", action="store_true",
                        help="Only regenerate DB and verify, skip pack generation")
    parser.add_argument("--offline", action="store_true",
                        help="Skip data directory refresh")
    parser.add_argument("--output-dir", default="dist",
                        help="Pack output directory (default: dist/)")
    parser.add_argument("--include-extras", action="store_true",
                        help="Include Tier 2 emulator extras in packs")
    args = parser.parse_args()

    results = {}
    all_ok = True
    total_start = time.monotonic()

    # Step 1: Generate database
    ok, out = run(
        [sys.executable, "scripts/generate_db.py", "--force",
         "--bios-dir", "bios", "--output", "database.json"],
        "1/5 generate database",
    )
    results["generate_db"] = ok
    if not ok:
        print("\nDatabase generation failed, aborting.")
        sys.exit(1)

    # Step 2: Refresh data directories
    if not args.offline:
        ok, out = run(
            [sys.executable, "scripts/refresh_data_dirs.py"],
            "2/5 refresh data directories",
        )
        results["refresh_data"] = ok
    else:
        print("\n--- 2/5 refresh data directories: SKIPPED (--offline) ---")
        results["refresh_data"] = True

    # Step 3: Verify
    verify_cmd = [sys.executable, "scripts/verify.py", "--all"]
    if args.include_archived:
        verify_cmd.append("--include-archived")
    ok, verify_output = run(verify_cmd, "3/5 verify all platforms")
    results["verify"] = ok
    all_ok = all_ok and ok

    # Step 4: Generate packs
    pack_output = ""
    if not args.skip_packs:
        pack_cmd = [
            sys.executable, "scripts/generate_pack.py", "--all",
            "--output-dir", args.output_dir,
        ]
        if args.include_archived:
            pack_cmd.append("--include-archived")
        if args.offline:
            pack_cmd.append("--offline")
        if args.include_extras:
            pack_cmd.append("--include-extras")
        ok, pack_output = run(pack_cmd, "4/5 generate packs")
        results["generate_packs"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 4/5 generate packs: SKIPPED (--skip-packs) ---")
        results["generate_packs"] = True

    # Step 5: Consistency check
    if pack_output and verify_output:
        ok = check_consistency(verify_output, pack_output)
        results["consistency"] = ok
        all_ok = all_ok and ok
    else:
        print("\n--- 5/5 consistency check: SKIPPED ---")
        results["consistency"] = True

    # Summary
    total_elapsed = time.monotonic() - total_start
    print(f"\n{'=' * 60}")
    for step, ok in results.items():
        print(f"  {step:.<40} {'OK' if ok else 'FAILED'}")
    print(f"  {'total':.<40} {total_elapsed:.1f}s")
    print(f"{'=' * 60}")
    print(f"  Pipeline {'COMPLETE' if all_ok else 'FINISHED WITH ERRORS'}")
    print(f"{'=' * 60}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
