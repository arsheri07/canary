#!/usr/bin/env python3
"""
test_canary.py - tests for hashing, entropy, diffing, and detection.

    python3 test_canary.py

No pytest needed.

The negative tests matter most. Anything can raise an alarm; the hard part is
staying quiet when a person is just doing their work. A file integrity monitor
that cries wolf gets uninstalled on day two.
"""

import os
import secrets
import shutil
import sys
import tempfile

from scanner import hash_file, shannon_entropy, scan_directory
from detect import compare, analyze_ransomware, risk_label, summarize

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok    {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def entry(h, entropy=4.0, size=1000, mtime=1.0):
    return {"hash": h, "entropy": entropy, "size": size, "mtime": mtime}


print("\nHASHING")
tmp = tempfile.mkdtemp()
a = os.path.join(tmp, "a.txt")
b = os.path.join(tmp, "b.txt")
open(a, "w").write("hello world")
open(b, "w").write("hello world")
check("identical content -> identical hash", hash_file(a) == hash_file(b))

open(b, "w").write("hello world!")
check("one changed byte -> different hash", hash_file(a) != hash_file(b))

check("hash is SHA-256 length (64 hex chars)", len(hash_file(a)) == 64)

big = os.path.join(tmp, "big.bin")
with open(big, "wb") as f:
    f.write(b"x" * (300 * 1024))  # bigger than one chunk
check("chunked reading handles multi-chunk files", len(hash_file(big)) == 64)


print("\nENTROPY")
check("empty input is 0", shannon_entropy(b"") == 0.0)
check("all-same bytes is 0", shannon_entropy(b"\x00" * 5000) == 0.0)

text = b"the quick brown fox jumps over the lazy dog " * 200
rand = secrets.token_bytes(8192)
check("English text lands 3.5-5.5", 3.5 < shannon_entropy(text) < 5.5,
      f"{shannon_entropy(text):.2f}")
check("random data lands above 7.5", shannon_entropy(rand) > 7.5,
      f"{shannon_entropy(rand):.2f}")
check("random scores higher than text", shannon_entropy(rand) > shannon_entropy(text))
check("never exceeds 8.0 (one byte = 8 bits)", shannon_entropy(rand) <= 8.0)


print("\nSCANNING")
scan_dir = tempfile.mkdtemp()
os.makedirs(os.path.join(scan_dir, "sub"))
os.makedirs(os.path.join(scan_dir, ".git"))
open(os.path.join(scan_dir, "one.txt"), "w").write("a")
open(os.path.join(scan_dir, "sub", "two.txt"), "w").write("b")
open(os.path.join(scan_dir, ".git", "config"), "w").write("should be ignored")

files, stats = scan_directory(scan_dir)
check("walks subdirectories", "one.txt" in files and os.path.join("sub", "two.txt") in files)
check("skips ignored directories", not any(".git" in p for p in files))
check("counts what it scanned", stats["scanned"] == 2, str(stats))
check("uses relative paths", all(not os.path.isabs(p) for p in files))


print("\nDIFF")
base = {"keep.txt": entry("aaa"), "edit.txt": entry("bbb"), "gone.txt": entry("ccc")}
now = {"keep.txt": entry("aaa"), "edit.txt": entry("BBB"), "new.txt": entry("ddd")}
changes = compare(base, now)
kinds = {c.path: c.kind for c in changes}

check("unchanged file produces no entry", "keep.txt" not in kinds)
check("changed hash -> modified", kinds.get("edit.txt") == "modified")
check("missing file -> deleted", kinds.get("gone.txt") == "deleted")
check("new file -> added", kinds.get("new.txt") == "added")
check("finds exactly 3 changes", len(changes) == 3)
check("identical snapshots -> no changes", compare(base, base) == [])


print("\nRANSOMWARE DETECTION")

# --- the important negative cases ---
normal = compare(
    {f"f{i}.txt": entry(f"h{i}", 4.0) for i in range(50)},
    {**{f"f{i}.txt": entry(f"h{i}", 4.0) for i in range(50)},
     "f3.txt": entry("changed", 4.1)},
)
score, _ = analyze_ransomware(normal)
check("editing one file stays NORMAL", risk_label(score) == "NORMAL", f"score={score}")

few = compare(
    {f"f{i}.txt": entry(f"h{i}", 4.0) for i in range(50)},
    {**{f"f{i}.txt": entry(f"h{i}", 4.0) for i in range(50)},
     **{f"f{i}.txt": entry(f"new{i}", 4.2) for i in range(5)}},
)
score, _ = analyze_ransomware(few)
check("editing five files stays NORMAL", risk_label(score) == "NORMAL", f"score={score}")

check("no changes -> score 0", analyze_ransomware([])[0] == 0)

# a zip being rebuilt is high-entropy but legitimate
zips = compare(
    {f"a{i}.zip": entry(f"h{i}", 7.9) for i in range(30)},
    {f"a{i}.zip": entry(f"new{i}", 7.9) for i in range(30)},
)
score, reasons = analyze_ransomware(zips)
check("rebuilding 30 zips does not trigger the entropy rule",
      not any("encrypted" in r for r in reasons), str(reasons))

# --- the positive cases ---
encrypted = compare(
    {f"doc{i}.txt": entry(f"h{i}", 4.0) for i in range(30)},
    {f"doc{i}.txt": entry(f"enc{i}", 7.9) for i in range(30)},
)
score, reasons = analyze_ransomware(encrypted)
check("30 docs encrypted in place -> HIGH or CRITICAL",
      risk_label(score) in ("HIGH", "CRITICAL"), f"score={score}")
check("names the entropy signal", any("encrypted" in r for r in reasons), str(reasons))

renamed = compare(
    {f"doc{i}.txt": entry(f"h{i}", 4.0) for i in range(30)},
    {f"doc{i}.txt.locked": entry(f"enc{i}", 7.9) for i in range(30)},
)
score, reasons = analyze_ransomware(renamed)
check("encrypt-and-rename -> CRITICAL", risk_label(score) == "CRITICAL", f"score={score}")
check("names the extension signal",
      any("extension" in r for r in reasons), str(reasons))

note = compare({}, {"HOW_TO_DECRYPT.txt": entry("x", 4.0)})
score, reasons = analyze_ransomware(note)
check("spots a ransom note", any("ransom note" in r for r in reasons), str(reasons))

check("score never exceeds 100", analyze_ransomware(renamed)[0] <= 100)


print("\nLABELS")
check("70+ is CRITICAL", risk_label(80) == "CRITICAL")
check("40-69 is HIGH", risk_label(50) == "HIGH")
check("20-39 is SUSPICIOUS", risk_label(25) == "SUSPICIOUS")
check("under 20 is NORMAL", risk_label(5) == "NORMAL")


print("\nEND TO END")
real = tempfile.mkdtemp()
for i in range(25):
    open(os.path.join(real, f"d{i}.txt"), "w").write("ordinary document text " * 60)

before, _ = scan_directory(real)
for i in range(20):
    with open(os.path.join(real, f"d{i}.txt"), "wb") as f:
        f.write(secrets.token_bytes(1400))
after, _ = scan_directory(real)

score, reasons = analyze_ransomware(compare(before, after))
check("real files encrypted on disk are detected",
      risk_label(score) in ("HIGH", "CRITICAL"), f"score={score} {reasons}")

# and the control: touching them normally is not
real2 = tempfile.mkdtemp()
for i in range(25):
    open(os.path.join(real2, f"d{i}.txt"), "w").write("ordinary document text " * 60)
b2, _ = scan_directory(real2)
with open(os.path.join(real2, "d1.txt"), "a") as f:
    f.write("one more line\n")
a2, _ = scan_directory(real2)
score2, _ = analyze_ransomware(compare(b2, a2))
check("appending a line to one real file stays NORMAL",
      risk_label(score2) == "NORMAL", f"score={score2}")

for d in (tmp, scan_dir, real, real2):
    shutil.rmtree(d, ignore_errors=True)

print("\n" + "=" * 46)
print(f"  {PASS} passed, {FAIL} failed")
print("=" * 46 + "\n")
sys.exit(1 if FAIL else 0)
