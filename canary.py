#!/usr/bin/env python3
"""
canary.py - file integrity monitor with ransomware detection.

    python3 canary.py baseline ~/Documents      take a fingerprint
    python3 canary.py check    ~/Documents      see what changed
    python3 canary.py watch    ~/Documents      check every 60s

File integrity monitoring is a required control under PCI-DSS 11.5 and CIS
Control 3. Tripwire and OSSEC are the enterprise versions of this idea.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from scanner import scan_directory
from detect import compare, analyze_ransomware, risk_label, summarize

USE_COLOR = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


COLORS = {"CRITICAL": "1;31", "HIGH": "31", "SUSPICIOUS": "33", "NORMAL": "32"}


def snapshot_path(target):
    """
    Where the baseline lives.

    Deliberately NOT inside the folder being watched - otherwise the snapshot
    file itself shows up as a change on every scan, and worse, ransomware that
    encrypts the folder would take the baseline with it.
    """
    home = os.path.expanduser("~")
    store = os.path.join(home, ".canary")
    os.makedirs(store, exist_ok=True)
    safe = os.path.abspath(target).replace(os.sep, "_").replace(":", "")
    return os.path.join(store, f"{safe}.json")


def save_snapshot(target, files, stats):
    path = snapshot_path(target)
    with open(path, "w") as f:
        json.dump({
            "target": os.path.abspath(target),
            "taken_at": datetime.now().isoformat(timespec="seconds"),
            "file_count": len(files),
            "stats": stats,
            "files": files,
        }, f, indent=1)
    return path


def load_snapshot(target):
    path = snapshot_path(target)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def cmd_baseline(args):
    if not os.path.isdir(args.target):
        print(f"error: not a directory: {args.target}", file=sys.stderr)
        return 1

    print(f"Scanning {os.path.abspath(args.target)} ...")
    t0 = time.time()
    files, stats = scan_directory(args.target, max_file_mb=args.max_size)
    elapsed = time.time() - t0

    path = save_snapshot(args.target, files, stats)

    print(f"\n  {stats['scanned']} files fingerprinted in {elapsed:.1f}s")
    if stats["skipped_large"]:
        print(f"  {stats['skipped_large']} skipped (over {args.max_size} MB)")
    if stats["unreadable"]:
        print(f"  {stats['unreadable']} unreadable (permissions)")
    print(f"\n  Baseline saved to {path}")
    print(f"  Run 'python3 canary.py check {args.target}' to detect changes.\n")
    return 0


def cmd_check(args):
    snap = load_snapshot(args.target)
    if not snap:
        print(f"error: no baseline for {os.path.abspath(args.target)}", file=sys.stderr)
        print(f"       run: python3 canary.py baseline {args.target}", file=sys.stderr)
        return 1

    files, stats = scan_directory(args.target, max_file_mb=args.max_size)
    changes = compare(snap["files"], files)
    score, reasons = analyze_ransomware(changes)
    label = risk_label(score)
    summary = summarize(changes)

    if args.json:
        print(json.dumps({
            "baseline_taken": snap["taken_at"],
            "risk_score": score,
            "risk_label": label,
            "reasons": reasons,
            "summary": summary,
            "changes": [{"kind": ch.kind, "path": ch.path, "detail": ch.detail}
                        for ch in changes],
        }, indent=2))
        return 2 if score >= 70 else 0

    print()
    print(c("=" * 64, "1"))
    print(c("  CANARY - file integrity check", "1"))
    print(c("=" * 64, "1"))
    print(f"  Watching : {snap['target']}")
    print(f"  Baseline : {snap['taken_at']}  ({snap['file_count']} files)")
    print(f"  Now      : {stats['scanned']} files")
    print()

    if not changes:
        print(c("  No changes. Everything matches the baseline.\n", "32"))
        print(c("=" * 64, "1"))
        print()
        return 0

    print(f"  {summary['total']} changes:  "
          + c(f"{summary['added']} added", "32") + "  "
          + c(f"{summary['modified']} modified", "33") + "  "
          + c(f"{summary['deleted']} deleted", "31"))
    print()

    # Verdict first - the whole point is that you see the alarm immediately
    bar = "#" * int(score / 5)
    print(c(f"  RISK: {label}  {bar}  {score}/100", COLORS[label]))
    if reasons:
        for r in reasons:
            print(c(f"    - {r}", COLORS[label]))
    else:
        print(c("    - changes look like ordinary file activity", "32"))
    print()

    if score >= 70:
        print(c("  >>> This pattern is consistent with active ransomware.", "1;31"))
        print(c("  >>> Disconnect this machine from the network and stop", "1;31"))
        print(c("  >>> any sync clients before restoring from backup.", "1;31"))
        print()

    limit = None if args.all else 25
    shown = changes[:limit] if limit else changes
    for ch in shown:
        mark = {"added": "+", "modified": "~", "deleted": "-"}[ch.kind]
        color = {"added": "32", "modified": "33", "deleted": "31"}[ch.kind]
        line = f"  {mark} {ch.path}"
        if ch.detail:
            line += c(f"   [{ch.detail}]", "90")
        print(c(line, color) if not ch.detail else c(f"  {mark} {ch.path}", color)
              + c(f"   [{ch.detail}]", "90"))

    if limit and len(changes) > limit:
        print(c(f"\n  ... {len(changes) - limit} more (use --all to see them)", "90"))

    print()
    print(c("=" * 64, "1"))
    print()

    if args.update:
        save_snapshot(args.target, files, stats)
        print("  Baseline updated to current state.\n")

    return 2 if score >= 70 else 0


def cmd_watch(args):
    """Re-check on a loop. This is how you would actually run it in the background."""
    if not load_snapshot(args.target):
        print("No baseline yet - taking one now.\n")
        cmd_baseline(args)

    print(f"Watching {os.path.abspath(args.target)} every {args.interval}s. Ctrl+C to stop.\n")
    try:
        while True:
            files, stats = scan_directory(args.target, max_file_mb=args.max_size)
            snap = load_snapshot(args.target)
            changes = compare(snap["files"], files)
            score, reasons = analyze_ransomware(changes)
            stamp = datetime.now().strftime("%H:%M:%S")

            if not changes:
                print(c(f"[{stamp}] ok - no changes", "90"))
            else:
                label = risk_label(score)
                s = summarize(changes)
                msg = (f"[{stamp}] {s['total']} changes "
                       f"(+{s['added']} ~{s['modified']} -{s['deleted']})  {label} {score}/100")
                print(c(msg, COLORS[label]))
                for r in reasons:
                    print(c(f"           {r}", COLORS[label]))
                if score >= 70:
                    print(c("           >>> POSSIBLE RANSOMWARE - disconnect now", "1;31"))

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.\n")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="File integrity monitor with ransomware detection.")
    sub = ap.add_subparsers(dest="command", required=True)

    for name, help_text in [("baseline", "fingerprint a directory"),
                            ("check", "compare against the baseline"),
                            ("watch", "check repeatedly")]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("target", help="directory to monitor")
        p.add_argument("--max-size", type=int, default=200,
                       help="skip files larger than this many MB")
        if name == "check":
            p.add_argument("--all", action="store_true", help="list every change")
            p.add_argument("--json", action="store_true", help="machine-readable")
            p.add_argument("--update", action="store_true",
                           help="accept the changes and re-baseline")
        if name == "watch":
            p.add_argument("--interval", type=int, default=60, help="seconds between checks")

    args = ap.parse_args()
    return {"baseline": cmd_baseline, "check": cmd_check, "watch": cmd_watch}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
