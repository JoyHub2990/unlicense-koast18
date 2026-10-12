"""Place wl-lic's dummy licence and RSA keys next to every prepared sample.

The guard agent (unlicense/license_guard.py) redirects the protection's licence
read to a file we control, and it needs two things from wl-lic:

* ``regkey.dat`` -- the dummy licence.  Stage 0's landmark is "a mapping whose
  first 8 bytes are the head of that file".
* ``regkey.rsa`` -- our RSA keys.  Stage 1 identifies the protection's
  mp_exptmod call by matching its arguments against these, so without them the
  matcher reports ``sub4-no-key-match ... rsaKeys=null matches=0`` and Stage 1
  never completes.  A hand-written blob with no keys is exactly that failure: it
  looks like the guard ran and found nothing, when in truth it was never given
  the keys to look for.

Both files come from spikes/build_wl_lic.py (which builds whatlicense's wl-lic),
the same source the spike2 harness uses, so a CI log from either path is
comparable.  Refuse to run when they are missing rather than writing a stand-in.
"""

import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMMY_DIR = ROOT / "results" / "spike2_dummy"
RESULTS = ROOT / "results"


def main() -> int:
    dummy = DUMMY_DIR / "regkey.dat"
    rsa = DUMMY_DIR / "regkey.rsa"
    build_info = RESULTS / "wl_lic_build.json"
    if not dummy.is_file() or not rsa.is_file():
        print(f"missing wl-lic output: {dummy} or {rsa}", flush=True)
        if build_info.is_file():
            print(f"wl_lic_build.json: {build_info.read_text()[:1200]}",
                  flush=True)
        print("run spikes/build_wl_lic.py first (it needs the whatlicense "
              "checkout); a licence without keys cannot arm Stage 1",
              flush=True)
        return 1

    head = dummy.read_bytes()[:8].hex()
    written = 0
    for root in [ROOT / "samples"]:
        if not root.is_dir():
            continue
        for pe in sorted(root.rglob("*")):
            if pe.suffix.lower() not in (".exe", ".dll"):
                continue
            shutil.copyfile(dummy, pe.parent / "regkey.dat")
            shutil.copyfile(rsa, pe.parent / "regkey.rsa")
            written += 1
    print(f"copied wl-lic licence (head {head}) and keys next to "
          f"{written} sample(s)", flush=True)
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
