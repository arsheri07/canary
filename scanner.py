#!/usr/bin/env python3
"""
scanner.py - walk a directory and fingerprint every file.

WHAT A FINGERPRINT IS

A hash function takes any amount of data and produces a fixed-length string.
The useful property: change even one byte of the input and the output changes
completely. So if a file's hash is the same today as yesterday, the file is
byte-for-byte identical. If the hash changed, something edited it.

We use SHA-256. MD5 and SHA-1 are faster but both are broken for security use -
an attacker can craft two different files with the same MD5, which would let
them swap a file without the hash changing. That is exactly the attack a file
integrity monitor exists to stop, so using a broken hash would defeat the point.

WHY WE READ IN CHUNKS

    hashlib.sha256(open(path,'rb').read())   # loads the WHOLE file into RAM

That works fine until someone points this at a 4 GB disk image. Reading in
64 KB chunks keeps memory flat no matter how big the file is.
"""

import hashlib
import math
import os
from collections import Counter

CHUNK_SIZE = 65536  # 64 KB


def hash_file(path):
    """SHA-256 of a file's contents, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data):
    """
    Measure how random a chunk of bytes looks. Returns 0.0 to 8.0.

    THE IDEA
    Entropy answers "how surprising is the next byte?"

    English text is predictable - lots of 'e' and ' ', almost no 0x00. Low
    entropy, usually 4 to 5.

    Encrypted or compressed data is designed to look like noise. Every byte
    value appears about equally often, so nothing is predictable. High entropy,
    usually above 7.5.

    THE FORMULA
        H = -sum(p * log2(p))  for each byte value that appears

    where p is that byte's share of the total. It maxes out at 8.0 because a
    byte has 8 bits - if all 256 values are equally likely, you need all 8 bits
    to describe which one came next.

    WHY IT MATTERS HERE
    Ransomware encrypts your files. Encrypted output has high entropy. So a
    document whose entropy jumps from 4.5 to 7.9 was almost certainly encrypted,
    not edited. That single number is the difference between "Bob revised the
    quarterly report" and "the quarterly report is now unrecoverable."
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def sample_entropy(path, sample_bytes=8192):
    """
    Entropy of the first 8 KB, not the whole file.

    Reading every byte of every file would make scans slow for no real benefit -
    encryption applies uniformly, so the first 8 KB is representative. This is
    a deliberate speed/accuracy tradeoff, and it is the right one here.
    """
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(sample_bytes))
    except (OSError, PermissionError):
        return 0.0


def scan_directory(root, ignore_dirs=None, ignore_exts=None, max_file_mb=200):
    """
    Fingerprint every file under `root`.

    Returns a dict: {relative_path: {hash, size, mtime, entropy}}

    Using the RELATIVE path as the key matters - it means a baseline taken on
    one machine still works if the folder is moved, and it keeps absolute paths
    (which may contain your username) out of the saved snapshot.
    """
    ignore_dirs = set(ignore_dirs or [".git", "__pycache__", "node_modules",
                                      ".venv", "venv", ".idea"])
    ignore_exts = set(ignore_exts or [])
    max_bytes = max_file_mb * 1024 * 1024

    files = {}
    stats = {"scanned": 0, "skipped_large": 0, "unreadable": 0}

    for dirpath, dirnames, filenames in os.walk(root):
        # Modifying dirnames in place tells os.walk not to descend into them.
        # Doing it this way skips the whole subtree instead of walking it and
        # discarding results.
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]

        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in ignore_exts:
                continue

            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)

            try:
                st = os.stat(full)
                if st.st_size > max_bytes:
                    stats["skipped_large"] += 1
                    continue

                files[rel] = {
                    "hash": hash_file(full),
                    "size": st.st_size,
                    "mtime": round(st.st_mtime, 2),
                    "entropy": round(sample_entropy(full), 3),
                }
                stats["scanned"] += 1

            except (OSError, PermissionError):
                # A file we cannot read is worth counting but not worth crashing
                # over - permissions vary, and files disappear mid-scan.
                stats["unreadable"] += 1
                continue

    return files, stats
