"""Write a dummy licence next to every prepared sample.

The guard agent (unlicense/license_guard.py) redirects the protection's licence
read to a file we control, and Stage 0's landmark is "a mapping whose first 8
bytes are the head of that file".  The prepared samples ship no regkey.dat, so
without this step the guard has nothing to redirect to and the protection rejects
the run -- which looks exactly like the OEP timeout it is meant to fix.

The body is deterministic (i * 7 + 3) and the head is WLDUMY01, the same stand-in
spikes/run_spike2.py uses, so a CI log can be compared with a spike2 run.
"""

import sys
from pathlib import Path

HEAD = bytes([0x57, 0x4C, 0x44, 0x55, 0x4D, 0x59, 0x30, 0x31])  # WLDUMY01
SIZE = 4096


def make(path: Path) -> None:
    body = bytes((i * 7 + 3) & 0xFF for i in range(SIZE - len(HEAD)))
    path.write_bytes(HEAD + body)


def main() -> int:
    roots = [Path("samples")]
    written = 0
    for root in roots:
        if not root.is_dir():
            continue
        for pe in sorted(root.rglob("*")):
            if pe.suffix.lower() not in (".exe", ".dll"):
                continue
            target = pe.parent / "regkey.dat"
            make(target)
            written += 1
            print(f"dummy licence {target} ({SIZE} bytes)", flush=True)
    print(f"wrote {written} dummy licence(s)", flush=True)
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
