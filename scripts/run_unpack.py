#!/usr/bin/env python3
"""Run unlicense against every prepared sample whose PE bitness matches this
interpreter, collect per-sample outcomes, and write a markdown + JSON report.

Target selection per sample label:
  - prefer .exe over helper DLLs shipped in the archive
  - prefer PEs whose packer version was detected (v2/v3) over unknown ones

Statuses:
  OK          unpacked_<name> produced
  FAIL        unlicense ran but no dump (timeout / error rc)
  ERROR       crashed (frida attach failure, traceback)
  SKIP_ARCH   PE bitness != interpreter bitness (other matrix job handles it)
  SKIP_*      not downloadable / no PE

Exit code: 1 if any FAIL/ERROR, else 0.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RUNS = ROOT / "runs"

_GUARD = os.environ.get("UNLICENSE_GUARD") == "1"
# Windows measured, not guessed: with the guard armed, the attempts that were
# allowed 150s reached lic_copy recovery, licence-page guard hits and sub4-leave,
# while the ones cut at 90s produced nothing. The protection's licence check sits
# late in this process's startup, so the short window was cutting it off before
# it began.
PER_SAMPLE_TIMEOUT = int(
    os.environ.get("UNLICENSE_SAMPLE_TIMEOUT_S", "240" if _GUARD else "420"))
UNLICENSE_OEP_TIMEOUT = int(
    os.environ.get("UNLICENSE_OEP_TIMEOUT_S", "150" if _GUARD else "120"))


def interpreter_bitness() -> str:
    # process bitness, NOT platform.machine() (which reports AMD64 even for
    # 32-bit python on 64-bit Windows)
    return "x64" if sys.maxsize > 2**32 else "x86"


def kill_tree(proc: subprocess.Popen) -> None:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                   capture_output=True)


def select_targets(entry: dict) -> list:
    """Prefer real main executables over helper DLLs, and known-version PEs."""
    exes = [p for p in entry["pes"] if p["path"].lower().endswith(".exe")]
    cands = exes or entry["pes"]
    known = [p for p in cands if p.get("version") is not None]
    return known or cands


def run_one(pe_rel: str) -> dict:
    pe = ROOT / pe_rel
    label = Path(pe_rel).stem
    workdir = RUNS / label
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)

    cmd = [sys.executable, "-m", "unlicense", str(pe),
           "--timeout", str(UNLICENSE_OEP_TIMEOUT)]
    start = time.time()
    result = {"status": "FAIL", "rc": -1, "seconds": 0.0,
              "dumps": [], "tail": []}
    # Send the child's output straight to a file rather than a pipe.
    #
    # The first guarded run died on the hard kill with rc=-1 and the exception
    # path threw away everything the child had written, so a hang left no
    # evidence at all -- not even the guard's own "armed" lines. A file survives
    # the kill, and it is written to the same place the report reads.
    log_path = RESULTS / "logs" / f"{label}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as log:
            # The package is installed into site-packages, where there is no
            # spikes/ next to it, so point the guard at the checkout's agent.
            child_env = dict(os.environ)
            agent = ROOT / "spikes" / "spike2_agent.js"
            if agent.is_file():
                child_env["UNLICENSE_GUARD_AGENT"] = str(agent)
            proc = subprocess.Popen(cmd, cwd=workdir, stdout=log,
                                    stderr=subprocess.STDOUT, text=True,
                                    errors="replace", bufsize=1,
                                    env=child_env)
            try:
                proc.wait(timeout=PER_SAMPLE_TIMEOUT)
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=15)
        rc = proc.returncode
        out = log_path.read_text(encoding="utf-8", errors="replace")
        log_lines = out.splitlines()
        dumps = [d for d in workdir.glob("unpacked_*")
                 if d.is_file() and d.stat().st_size > 1024]

        if dumps:
            status = "OK"
        elif rc == -999:
            status = "FAIL"
        elif "Traceback" in (out or "") or "frida." in (out or ""):
            status = "ERROR"
        else:
            status = "FAIL"

        # Surface the guard's own lines: with the guard on, "why did the licence
        # check not let the OEP through" is the only question that matters, and
        # its answers are a handful of lines in a very chatty log.
        guard_lines = [line for line in log_lines
                       if "license_guard:" in line][-6:]
        tail = (guard_lines + log_lines[-6:])[-8:]
        result = {"status": status, "rc": rc,
                  "seconds": round(time.time() - start, 1),
                  "dumps": [d.name for d in dumps],
                  "tail": tail}
        out_dir = RESULTS / "unpacked"
        out_dir.mkdir(exist_ok=True)
        for d in dumps:
            shutil.copy(d, out_dir / f"{label}_{d.name}")
    except Exception as exc:  # noqa: BLE001
        result = {"status": "ERROR", "rc": -1,
                  "seconds": round(time.time() - start, 1),
                  "dumps": [], "tail": [f"runner exception: {exc}"]}
    return result


def main() -> int:
    sys.path.insert(0, str(ROOT))
    manifest = json.loads((RESULTS / "manifest.json").read_text())
    bitness = interpreter_bitness()
    print(f"interpreter bitness: {bitness}", flush=True)

    rows = []
    has_bad = False
    for entry in manifest:
        label = entry["label"]
        if not entry["downloaded"] or not entry["pes"]:
            rows.append({"label": label, "pe": "-", "arch": "-",
                         "version": "-", "status": entry["status"],
                         "rc": "-", "seconds": 0, "tail": []})
            continue
        for pe_info in select_targets(entry):
            if pe_info["arch"] != bitness:
                rows.append({"label": label,
                             "pe": Path(pe_info["path"]).name,
                             "arch": pe_info["arch"] or "?",
                             "version": pe_info["version"],
                             "status": "SKIP_ARCH", "rc": "-",
                             "seconds": 0, "tail": []})
                continue
            # Repeat when the guard is on.
            #
            # The landmark Stage 1 depends on is a per-attempt event: the spike2
            # harness buys attempts with --repeat 20 and completes Stage 1 in
            # roughly one in eight of them. The unpacker gets one run per sample
            # unless it repeats too, which is why every guarded unpack run so far
            # ended in an OEP timeout even though the guard was armed and its
            # licence-page hits were visible. See handoff 9.58.
            attempts = 1
            if os.environ.get("UNLICENSE_GUARD") == "1":
                attempts = max(
                    1, int(os.environ.get("UNLICENSE_GUARD_ATTEMPTS", "4")))
            res = {"status": "FAIL", "rc": -1, "seconds": 0.0, "dumps": [],
                   "tail": []}
            for attempt in range(1, attempts + 1):
                print(f"[{label}] running {pe_info['path']} "
                      f"(v{pe_info['version']}) attempt {attempt}/{attempts} ...",
                      flush=True)
                res = run_one(pe_info["path"])
                print(f"[{label}] -> {res['status']} rc={res['rc']} "
                      f"{res['seconds']}s dumps={res['dumps']}", flush=True)
                for line in res.get("tail", []):
                    print(f"[{label}]   {line}", flush=True)
                # Retry while there is no dump. The "OEP not reached" outcome
                # surfaces two ways: rc=4 (unlicense exits after its own timeout)
                # and rc=1 with frida.InvalidOperationError: script has been
                # destroyed (the timeout path terminated the process and the
                # next RPC then failed). Keying on rc=4 alone stopped retrying
                # after the first attempt in round 9 for exactly that reason.
                if res["dumps"]:
                    break
            if res["status"] in ("FAIL", "ERROR"):
                has_bad = True
            rows.append({"label": label, "pe": Path(pe_info["path"]).name,
                         "arch": pe_info["arch"], "version": pe_info["version"],
                         **res})

    report = {"bitness": bitness, "rows": rows,
              "ok": sum(1 for r in rows if r["status"] == "OK"),
              "fail": sum(1 for r in rows
                          if r["status"] in ("FAIL", "ERROR"))}
    (RESULTS / f"report_{bitness}.json").write_text(json.dumps(report, indent=2))

    md = [f"## Unpack report (python {bitness})", "",
          "| sample | PE | ver | status | rc | sec | tail |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        tail = " / ".join(t.strip() for t in r.get("tail", [])[-2:])[:160]
        tail = tail.replace("|", "\\|").replace("\r", " ")
        md.append(f"| {r['label']} | {r['pe']} | {r['version']} | "
                  f"{r['status']} | {r['rc']} | {r.get('seconds', 0)} | "
                  f"`{tail}` |")
    md.append("")
    md.append(f"**OK: {report['ok']}  FAIL/ERROR: {report['fail']}**")
    summary = "\n".join(md) + "\n"
    print(summary, flush=True)
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as f:
            f.write(summary)

    return 1 if has_bad else 0


if __name__ == "__main__":
    sys.exit(main())
