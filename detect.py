#!/usr/bin/env python3
"""
detect.py - compare two snapshots and decide what the changes mean.

Comparing snapshots is easy: three set operations tell you what was added,
deleted, or modified.

Interpreting the result is the actual work. A folder where 40 files changed
could be:
  - you saved a document                       (fine)
  - you ran a build                            (fine)
  - ransomware encrypting everything you own   (not fine)

The difference is in the SHAPE of the changes, not the count.
"""

import os
from collections import Counter

# Extensions ransomware commonly appends. Not exhaustive - families invent new
# ones constantly - which is exactly why this is only ONE of several signals.
RANSOM_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".crypto", ".enc", ".locky",
    ".wannacry", ".wcry", ".cerber", ".zepto", ".odin", ".aesir",
    ".ryuk", ".conti", ".lockbit", ".darkside", ".revil", ".sodinokibi",
}

# Filenames ransomware drops to tell you how to pay
RANSOM_NOTE_HINTS = ("readme", "decrypt", "how_to", "howto", "recover",
                     "restore", "ransom", "your_files")

# File types that are SUPPOSED to have high entropy. A .zip or .jpg is already
# compressed, so its entropy is naturally ~7.9. Flagging those would produce
# constant false positives.
NATURALLY_HIGH_ENTROPY = {".zip", ".gz", ".7z", ".rar", ".jpg", ".jpeg",
                          ".png", ".gif", ".mp4", ".mp3", ".avi", ".mkv",
                          ".pdf", ".docx", ".xlsx", ".pptx", ".woff", ".woff2"}

ENTROPY_ENCRYPTED = 7.5   # above this, contents look like noise
ENTROPY_JUMP = 2.0        # a rise this large is suspicious on its own


class Change:
    """One difference between two snapshots."""

    def __init__(self, kind, path, detail="", old=None, new=None):
        self.kind = kind      # added | modified | deleted
        self.path = path
        self.detail = detail
        self.old = old or {}
        self.new = new or {}

    def __repr__(self):
        return f"<{self.kind} {self.path}>"


def compare(baseline, current):
    """
    Diff two snapshots.

    Set operations do the heavy lifting - this is the whole comparison:
        added    = current - baseline
        deleted  = baseline - current
        common   = both, then check whether the hash moved
    """
    old_paths = set(baseline)
    new_paths = set(current)

    changes = []

    for path in sorted(new_paths - old_paths):
        changes.append(Change("added", path, new=current[path]))

    for path in sorted(old_paths - new_paths):
        changes.append(Change("deleted", path, old=baseline[path]))

    for path in sorted(old_paths & new_paths):
        if baseline[path]["hash"] != current[path]["hash"]:
            old_e = baseline[path].get("entropy", 0)
            new_e = current[path].get("entropy", 0)
            detail = f"entropy {old_e:.2f} -> {new_e:.2f}"
            changes.append(Change("modified", path, detail,
                                  old=baseline[path], new=current[path]))

    return changes


# ---------------------------------------------------------------------------
# Ransomware heuristics
#
# No single signal is reliable on its own. A legitimate program can produce any
# ONE of these. What almost nothing legitimate does is produce SEVERAL AT ONCE.
# So each check contributes to a score, and the score is what raises the alarm.
# ---------------------------------------------------------------------------
def analyze_ransomware(changes):
    """
    Look at the whole set of changes and decide whether this looks like an
    encryption event.

    Returns (score 0-100, list of human-readable reasons).
    """
    score = 0
    reasons = []

    modified = [c for c in changes if c.kind == "modified"]
    added = [c for c in changes if c.kind == "added"]
    deleted = [c for c in changes if c.kind == "deleted"]

    if not changes:
        return 0, []

    # --- SIGNAL 1: many files modified at once ---
    # You edit a handful of files at a time. Ransomware processes hundreds.
    if len(modified) >= 50:
        score += 30
        reasons.append(f"{len(modified)} files modified in a single interval")
    elif len(modified) >= 20:
        score += 15
        reasons.append(f"{len(modified)} files modified in a single interval")

    # --- SIGNAL 2: entropy jumped on files that should be low-entropy ---
    # This is the strongest single indicator.
    encrypted_looking = []
    for c in modified:
        ext = os.path.splitext(c.path)[1].lower()
        if ext in NATURALLY_HIGH_ENTROPY:
            continue  # a .zip is meant to look random
        old_e = c.old.get("entropy", 0)
        new_e = c.new.get("entropy", 0)
        if new_e >= ENTROPY_ENCRYPTED and (new_e - old_e) >= ENTROPY_JUMP:
            encrypted_looking.append(c.path)

    if len(encrypted_looking) >= 10:
        score += 40
        reasons.append(f"{len(encrypted_looking)} files now contain "
                       f"high-entropy data (contents look encrypted)")
    elif len(encrypted_looking) >= 3:
        score += 25
        reasons.append(f"{len(encrypted_looking)} files now contain "
                       f"high-entropy data (contents look encrypted)")

    # --- SIGNAL 3: known ransomware extensions appeared ---
    ransom_ext_files = [c.path for c in added
                        if os.path.splitext(c.path)[1].lower() in RANSOM_EXTENSIONS]
    if ransom_ext_files:
        score += 35
        exts = {os.path.splitext(p)[1].lower() for p in ransom_ext_files}
        reasons.append(f"{len(ransom_ext_files)} new files with known "
                       f"ransomware extensions ({', '.join(sorted(exts))})")

    # --- SIGNAL 4: a ransom note appeared ---
    notes = [c.path for c in added
             if any(h in os.path.basename(c.path).lower() for h in RANSOM_NOTE_HINTS)
             and os.path.splitext(c.path)[1].lower() in (".txt", ".html", ".hta", "")]
    if notes:
        score += 20
        reasons.append(f"possible ransom note: {notes[0]}")

    # --- SIGNAL 5: mass delete paired with mass create ---
    # Some ransomware writes a new encrypted file and deletes the original,
    # rather than modifying in place. This is actually the MORE common pattern.
    if len(deleted) >= 20 and len(added) >= 20:
        score += 25
        reasons.append(f"{len(deleted)} files deleted while {len(added)} "
                       f"new files appeared (encrypt-and-replace pattern)")

    # --- SIGNAL 6: the newly created files themselves look encrypted ---
    #
    # Signals 1 and 2 only inspect MODIFIED files, so an attacker who renames
    # instead of editing in place slips past both - the encrypted content lands
    # in an "added" entry that nothing was checking. That is a real gap, and
    # encrypt-and-rename is the more common pattern, so it mattered.
    #
    # Only applied when a mass replacement is already underway, otherwise
    # copying a folder of photos in would light this up.
    if len(added) >= 10 and len(deleted) >= 10:
        high_entropy_new = []
        for ch in added:
            ext = os.path.splitext(ch.path)[1].lower()
            if ext in NATURALLY_HIGH_ENTROPY:
                continue
            if ch.new.get("entropy", 0) >= ENTROPY_ENCRYPTED:
                high_entropy_new.append(ch.path)

        if len(high_entropy_new) >= 10:
            score += 30
            reasons.append(f"{len(high_entropy_new)} newly created files "
                           f"contain high-entropy data (replacement files "
                           f"look encrypted)")

    return min(100, score), reasons


def risk_label(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "SUSPICIOUS"
    return "NORMAL"


def summarize(changes):
    """Counts and a breakdown by file type, for the report header."""
    kinds = Counter(c.kind for c in changes)
    exts = Counter(os.path.splitext(c.path)[1].lower() or "(no ext)"
                   for c in changes)
    return {
        "added": kinds["added"],
        "modified": kinds["modified"],
        "deleted": kinds["deleted"],
        "total": len(changes),
        "top_extensions": exts.most_common(5),
    }
