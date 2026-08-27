# Canary — file integrity monitor with ransomware detection

Point it at a folder. It fingerprints every file. Later, it tells you exactly
what changed — and whether those changes look like an attack rather than
someone doing their job.

```
$ python3 canary.py check ~/Documents

================================================================
  CANARY - file integrity check
================================================================
  Watching : /Users/you/Documents
  Baseline : 2026-08-26T21:14:02  (55 files)

  112 changes:  57 added  0 modified  55 deleted

  RISK: CRITICAL  ################  90/100
    - 20 new files with known ransomware extensions (.locked)
    - 20 files deleted while 20 new files appeared (encrypt-and-replace pattern)
    - 20 newly created files contain high-entropy data

  >>> This pattern is consistent with active ransomware.
  >>> Disconnect this machine from the network and stop
  >>> any sync clients before restoring from backup.
```

File integrity monitoring is a required control under **PCI-DSS requirement
11.5** and **CIS Control 3**. Tripwire and OSSEC are the enterprise versions of
this idea. This is a small one you can actually read.

## Why you'd run it

Ransomware works through your files one at a time. By the time you notice
something is wrong, it has usually finished. Canary is meant to run on a timer
against the folders you care about, so you find out in the first minute — while
disconnecting the machine still saves most of your data.

It is also just a useful thing to have. Point it at a config directory, a
project, or a web root and you get an exact answer to "what changed since
Tuesday."

```bash
python3 canary.py baseline ~/Documents    # fingerprint everything
python3 canary.py check    ~/Documents    # what changed?
python3 canary.py watch    ~/Documents    # re-check every 60s
python3 test_canary.py                    # 36 tests
```

Standard library only. No dependencies, no install.

Useful flags: `--all` (list every change), `--json`, `--update` (accept the
changes and re-baseline), `--interval` (seconds, for `watch`).

Exit code is 2 on CRITICAL, so it can drive a cron job or a script.

## How it works

**1. Fingerprint.** SHA-256 of every file's contents. Change one byte and the
hash changes completely, so identical hash means identical file. MD5 would be
faster, but MD5 collisions are computable — an attacker could swap a file
without the hash moving, which is precisely the attack this tool exists to
catch. Files are read in 64 KB chunks so a 4 GB file doesn't get loaded into
memory.

**2. Compare.** Three set operations against the saved snapshot:

```
added    = current - baseline
deleted  = baseline - current
modified = in both, but the hash moved
```

**3. Interpret.** This is the actual work. Forty files changing could be a
build, or it could be an attack.

## The entropy idea

The interesting part.

Entropy measures how random data looks, on a scale of 0 to 8:

```
H = -sum(p * log2(p))    for each byte value present
```

English text is predictable — lots of `e` and space, almost no `0x00`. Entropy
lands around 4 to 5. Encrypted data is *designed* to look like noise, so every
byte value shows up about equally often. Entropy goes above 7.5.

So a document whose entropy jumps from 4.5 to 7.9 wasn't edited. It was
encrypted.

Measured on real data:

| Content | Entropy |
|---|---|
| English prose | 4.40 |
| Random / encrypted bytes | 7.98 |
| All zeros | 0.00 |

Files that are *supposed* to be high entropy — `.zip`, `.jpg`, `.mp4`, `.pdf` —
are excluded, because they're already compressed and would otherwise trigger
constantly.

## Detection signals

No single signal is trustworthy alone; a legitimate program can produce any one
of them. Almost nothing legitimate produces several at once, so each one adds to
a score.

| Signal | Points | Reasoning |
|---|---|---|
| 50+ files modified at once | 30 | People edit a few files. Ransomware processes hundreds. |
| Entropy jumped on modified files | 40 | Contents now look encrypted |
| Known ransomware extension appeared | 35 | `.locked`, `.crypt`, `.ryuk`, and similar |
| Ransom note dropped | 20 | `HOW_TO_DECRYPT.txt` and variants |
| Mass delete + mass create | 25 | Encrypt-and-replace pattern |
| New files are high-entropy | 30 | The replacements look encrypted |

**70+ = CRITICAL, 40–69 = HIGH, 20–39 = SUSPICIOUS, below = NORMAL.**

## A bug worth mentioning

The first version scored *encrypt-and-rename* lower than *encrypt-in-place* —
60 versus 70. That's backwards, because renaming is the more common pattern.

The cause: renaming a file produces an `added` entry and a `deleted` entry, and
never a `modified` one. Both entropy checks only inspected modified files, so
the encrypted content landed somewhere nothing was looking.

The fix was signal 6 — check entropy on newly created files too, but only when
a mass replacement is already underway, otherwise copying in a folder of photos
would set it off.

Worth noting because the code ran correctly the whole time. Nothing crashed. It
just quietly scored the most common real-world attack lower than the rarer one,
and only a test comparing the two cases against each other exposed it.

## Testing

36 tests: `python3 test_canary.py`

The **negative** tests are the ones that matter. A file integrity monitor that
cries wolf gets uninstalled on day two:

- editing one file stays NORMAL
- editing five files stays NORMAL
- rebuilding 30 `.zip` files does **not** trigger the entropy rule
- appending a line to a real file on disk stays NORMAL
- identical snapshots produce zero changes

And the positive ones run against real files on disk, not just mock data — 25
documents created, 20 overwritten with random bytes, verified detected.

## Limitations

- **Point-in-time, not real-time.** `watch` polls on an interval. A proper
  implementation would use filesystem events (`inotify` on Linux, FSEvents on
  macOS) to react instantly.
- **The baseline is a trust anchor.** It lives in `~/.canary/`, outside the
  watched folder, but it isn't signed. Malware with write access could tamper
  with it. Signing the snapshot is the obvious hardening step.
- **Extension list needs maintenance.** New ransomware families invent new
  extensions constantly, which is exactly why that signal is one of six rather
  than the whole detector.
- **Thresholds are fixed.** A folder that legitimately churns hundreds of files
  needs its own tuning; a real deployment would learn a per-directory baseline.
