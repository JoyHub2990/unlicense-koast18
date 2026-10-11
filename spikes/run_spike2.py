#!/usr/bin/env python3
"""Spike 2 host driver — Stage 0 (license copy location) of the whatlicense
pipeline, ported to Frida.

Two modes:

  --local   build spikes/spike2_target.c, write a dummy license, run the
            target with the agent attached (mmap/munmap hooks on Linux) and
            require the full Stage 0 result: the license is recognised when
            mapped, byte-store candidates are recorded, and after the unmap
            one candidate holds the license head -> lic_copy. Seconds, no CI.

  --ci      run a real WinLicense sample (from results/manifest.json, built by
            scripts/prepare_samples.py) with the NtCreateFile redirect,
            MapViewOfFile / UnmapViewOfFile hooks and the dummy license
            produced by wl-lic. A sample that never opens regkey.dat is
            reported as inconclusive, not as a harness failure.

The acceptance criterion for both is Stage 0's own: find `lic_copy`.
"""
import argparse
import json
import threading
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPIKES = ROOT / "spikes"
RESULTS = ROOT / "results"


def load_agent_source() -> str:
    """Concatenate the agent modules into one script.

    Frida evaluates a single source string, so the helper modules are inlined
    ahead of the main agent. Their ``module.exports`` guards are inert here
    (``module`` is undefined inside the agent runtime), which is exactly why
    the modules are safe to concatenate.
    """
    parts = []
    for name in ("hwbreak_agent.js", "spike2_agent.js"):
        path = SPIKES / name
        if path.exists():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


BUILD = RESULTS / "spike2_build"

IS_WINDOWS = sys.platform == "win32"
ARCH = "x64" if sys.maxsize > 2 ** 32 else "x86"

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(SPIKES))

import toolchain  # noqa: E402

HEAD_LEN = 8


def build_target(opt: int) -> Path:
    BUILD.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if IS_WINDOWS else ""
    out = BUILD / f"spike2_target_{sys.platform}_{ARCH}_O{opt}{suffix}"
    result = toolchain.compile_c(SPIKES / "spike2_target.c", out, opt)
    if not result["ok"]:
        raise SystemExit(f"build failed: {result}")
    print(f"built {out} ({out.stat().st_size} bytes) with "
          f"{result['compiler']}", flush=True)
    return out


def make_dummy_license(path: Path, size: int = 4096) -> str:
    """A stand-in for wl-lic's dummy license: the only thing Stage 0 needs is
    the first 8 bytes (it compares the head of the mapping)."""
    head = bytes([0x57, 0x4C, 0x44, 0x55, 0x4D, 0x59, 0x30, 0x31])  # WLDUMY01
    body = bytes((i * 7 + 3) & 0xFF for i in range(size - HEAD_LEN))
    path.write_bytes(head + body)
    return head.hex()


def read_rsa_keys(path: Path) -> dict:
    """Parse wl-lic's RSA output: 4 length bytes (in mp_digits) then the four
    digit arrays. mp_digit is 32-bit on the 32-bit target, so a length of n
    digits is n*4 bytes."""
    data = path.read_bytes()
    lengths = {"mod1": data[0], "exp1": data[1], "mod2": data[2],
               "exp2": data[3]}
    offset = 4
    keys = {}
    for name, length in lengths.items():
        chunk = data[offset:offset + length * 4]
        offset += length * 4
        keys[name] = chunk.hex()
        keys[name + "Len"] = length
    return keys


def windows_nt_path(path: Path) -> str:
    absolute = str(path.resolve())
    if not absolute.startswith("\\\\"):
        return "\\??\\" + absolute
    return absolute


def rpc_with_timeout(call, seconds: float = 15.0):
    """Run an frida RPC call with a deadline.

    A deadlocked agent (e.g. a frida API called from inside a Stalker callout)
    makes the RPC block forever, which hung a CI job until its 90 minute
    timeout. Returns ("timeout", None) instead.
    """
    box = {}

    def worker():
        try:
            box["value"] = call()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        return "timeout", None
    if "error" in box:
        return "error", box["error"]
    return "ok", box.get("value")


def run_agent(exe: Path, workdir: Path, head_hex: str, nt_path: str,
              duration: int, license_file: str,
              rsa_keys: dict = None, defer_tracing: bool = False) -> dict:
    import frida

    workdir.mkdir(parents=True, exist_ok=True)
    go_file = workdir / "spike_go"
    exit_file = workdir / "spike_exit"
    for path in (go_file, exit_file):
        path.unlink(missing_ok=True)

    device = frida.get_local_device()
    output = {"text": ""}
    messages = []

    device.on("output", lambda pid, fd, data: output.__setitem__(
        "text", output["text"] + data.decode("utf-8", "replace")))

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message["payload"]
            messages.append(payload)
            # Surface the agent's own stage/Stage-1 log in the CI log as it
            # happens. The verdict only ever printed the first 12 event names,
            # so the interesting part of a run that reached sub-stage 5 (the
            # mp_exptmod address, the per-call arguments, the swap/complete
            # lines) never left the artifact.
            if isinstance(payload, dict):
                spike = payload.get("spike")
                if spike == "stage1":
                    print("    spike2: stage1 " + str(payload.get("event")) +
                          " " + str(payload.get("detail")), flush=True)
                elif spike == "stage2":
                    # Stage 2's events were appended to messages (and so reached
                    # the report JSON) but never printed, so a real run that
                    # completed Stage 1 showed nothing about Stage 2 at all --
                    # indistinguishable from Stage 2 never having started.
                    print("    spike2: stage2 " + str(payload.get("event")) +
                          " " + str(payload.get("detail")), flush=True)
                elif spike in ("lic_copy", "lic_copy_missing", "lic_mapped",
                               "byte-store-unresolved", "exit"):
                    print("    spike2: " + spike + " " +
                          json.dumps(payload)[:400], flush=True)
        else:
            messages.append({"spike": "message", "raw": message})

    started = time.time()
    pid = device.spawn([str(exe)], cwd=str(workdir), stdio="pipe")
    session = device.attach(pid)
    script = session.create_script(load_agent_source())
    script.on("message", on_message)
    script.load()

    # Arm the hooks and Stalker BEFORE resuming: a real sample starts doing
    # file I/O (and may open its license) immediately, so a setup() after
    # resume() misses everything that happens in the first second -- which is
    # exactly what the first two CI runs measured (0 file opens observed
    # while the target was demonstrably running).
    license_size = 0
    try:
        license_size = Path(license_file).stat().st_size
    except OSError:
        pass
    setup = script.exports_sync.setup({
        "headHex": head_hex,
        "ntPath": nt_path,
        "licenseFile": license_file,
        "licSize": license_size,
        "rsaKeys": rsa_keys,
        "deferTracing": defer_tracing,
        # A real sample calls the RSA routine once (see stage1CallThreshold in
        # the agent); the mimic needs whatlicense's dec_sections + 1.
        "stage1CompleteAfter": int(os.environ.get("STAGE1_COMPLETE_AFTER", "0"))
    })
    device.resume(pid)
    # Stalker only takes effect on a running thread. With --defer-tracing the
    # agent refuses this call and starts the trace from the MapViewOfFile hook
    # instead, so the protection's own unpacking runs at native speed.
    _, tracing = rpc_with_timeout(lambda: script.exports_sync.start_tracing())
    print(f"  tracing: {json.dumps(tracing)}", flush=True)
    # Unblocks the mimic target; harmless for a real sample.
    go_file.write_text("go")

    status = None
    stage0_reported = False
    stage1_reported = False
    landmark_at = None
    deadline = time.time() + duration
    last_report = 0.0
    while time.time() < deadline:
        time.sleep(2)
        outcome, value = rpc_with_timeout(
            lambda: script.exports_sync.status())
        if outcome != "ok":
            # The agent dies with the process (or deadlocks); that is not a
            # harness failure -- everything already reported through send()
            # is still in `messages`.
            status = {"error": str(value), "processGone": True,
                      "rpcOutcome": outcome}
            break
        status = value
        if not stage0_reported and status.get("licCopy"):
            stage0_reported = True
            print(f"  stage0 complete: lic_copy={status['licCopy']}",
                  flush=True)
        # Stage 0 finishing is not the end any more: Stage 1 (the RSA chain)
        # is what this run is for, so keep going until it completes or the
        # duration runs out.
        # Stage 1 finishing is not the end any more: Stage 2 (the hash_3
        # comparison) runs on the decrypted buffer Stage 1 produced, so keep
        # going until Stage 2 completes or the duration runs out.
        if (status.get("stage2Sub") or 0) >= 3:
            print("  stage2 complete", flush=True)
            break
        if status.get("stage1Complete") or (status.get("stage1Sub") or 0) >= 6:
            if not stage1_reported:
                stage1_reported = True
                print("  stage1 complete", flush=True)
            # Do NOT break. Stage 2 runs on the decrypted buffer Stage 1
            # produced, and it needs the rest of the window: breaking here tore
            # the run down the moment Stage 1 finished, which is why every real
            # completion showed stage2Sub=0 (round 18: ngahost#3/#13 completed
            # Stage 1 and Stage 2 never started). Keep polling until Stage 2
            # completes or the duration runs out.
        # The landmark, when it is taken at all, is taken within ~45s and the
        # target then exits on the rejected license. Waiting out the rest of
        # the window only adds dead time to every run that did hit, so close
        # the run a short while after the landmark and let the repeat counter
        # buy more attempts instead.
        if (status.get("stage1Sub") or 0) >= 2:
            if landmark_at is None:
                landmark_at = time.time()
                print("  landmark taken (stage1Sub>=2); collecting "
                      "sub-stage data", flush=True)
            elif time.time() - landmark_at >= 25:
                # Close early only while Stage 1 is the thing being measured.
                # Once Stage 1 has completed, Stage 2 is running on the
                # decrypted buffer and needs the rest of the window -- this
                # break was the second place the run was torn down before
                # Stage 2 could do anything.
                if status.get("stage1Complete") or \
                        (status.get("stage2Sub") or 0) > 0:
                    pass
                else:
                    print("  landmark window closed", flush=True)
                    break
        if time.time() - last_report >= 15:
            last_report = time.time()
            print(f"  ... {status}", flush=True)
    print(f"  status: {json.dumps(status)}", flush=True)

    outcome, value = rpc_with_timeout(
        lambda: script.exports_sync.finish(), 20.0)
    if outcome == "ok":
        final = value
    else:
        final = {"error": f"finish rpc failed: {value}"}
        final.update(report_from_messages(messages, status))

    exit_file.write_text("exit")
    time.sleep(0.3)
    try:
        device.kill(pid)
    except Exception:  # noqa: BLE001
        pass
    try:
        session.detach()
    except Exception:  # noqa: BLE001
        pass

    return {
        "exe": str(exe),
        "seconds": round(time.time() - started, 1),
        "target_stdout": output["text"],
        "setup": setup,
        "status": status,
        "messages": messages,
        "final": final,
    }


def report_from_messages(messages: list, status: dict) -> dict:
    """Reconstruct the Stage 0 outcome from the send() stream.

    Needed whenever the target exits before finish(): the frida script is
    destroyed with the process, so the final RPC is gone, but every
    interesting event was already emitted.

    Stage 1/2 progress is rebuilt here too. Without it a run that took the
    landmark and reached sub-stage 2 before the target exited reported
    "sub-stage None" -- the most interesting outcome of the whole session was
    invisible in the report (ngahost, first real-target landmark).
    """
    report = {"reconstructedFromMessages": True,
              "openedPaths": [], "errors": []}
    candidates = set()
    stage1_events = []
    stage2_events = []
    exits = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        kind = message.get("spike")
        if kind == "redirect":
            report["originalLicensePath"] = message.get("original")
            report.setdefault("redirects", 0)
            report["redirects"] += 1
        elif kind == "lic_mapped":
            report["licenseMappedTo"] = message.get("addr")
        elif kind == "candidate":
            candidates.add(message.get("ea"))
        elif kind == "lic_copy":
            report["licCopy"] = message.get("addr")
            report["licCopyFirstBytes"] = message.get("bytes")
            report["candidates"] = sorted(candidates)
        elif kind == "lic_copy_missing":
            report["licCopyMissing"] = message
        elif kind == "stage1":
            stage1_events.append(message)
        elif kind == "stage2":
            stage2_events.append(message)
        elif kind == "exit":
            exits.append(message)
    if stage1_events:
        report["stage1"] = {
            "reconstructed": True,
            "events": [m.get("event") for m in stage1_events],
            "detail": [(m.get("event"), m.get("detail")) for m in stage1_events][-8:],
            "landmark": any(m.get("event") == "sub1-landmark-module"
                            for m in stage1_events),
            "hooked": sum(1 for m in stage1_events
                          if m.get("event") == "sub2-hooked"),
        }
    if stage2_events:
        report["stage2"] = {
            "reconstructed": True,
            "events": [m.get("event") for m in stage2_events][-8:],
        }
    if exits:
        report["exits"] = exits[:4]
    if isinstance(status, dict):
        report["stats"] = {
            "redirects": status.get("redirects", report.get("redirects", 0)),
            "fileOpens": status.get("fileOpens", 0),
            "byteWrites": status.get("byteWrites", 0),
            "byteStoresPlanned": status.get("byteStoresPlanned", 0),
            "rwNoMap": status.get("rwNoMap", 0),
            "rwNoTid": status.get("rwNoTid", 0),
            "rwNoByte": status.get("rwNoByte", 0),
            "rwByteMismatch": status.get("rwByteMismatch", 0),
            "byteWritesFromMem": status.get("byteWritesFromMem", 0),
            "byteStoresSystem": status.get("byteStoresSystem", 0),
            "instructions": status.get("instructions", 0),
            "threads": status.get("threads", ""),
            "processGone": status.get("processGone", False)
        }
        if status.get("openedPaths"):
            report["openedPaths"] = status["openedPaths"]
    return report


def judge_local(run: dict, head_hex: str) -> dict:
    final = run.get("final", {})
    mapped = bool(final.get("licenseMappedTo"))
    candidates = final.get("candidates") or []
    lic_copy = final.get("licCopy")
    checks = {
        "license-mapped": {
            "ok": mapped,
            "detail": f"mapping at {final.get('licenseMappedTo')} had head "
                      f"{head_hex}",
        },
        "candidates-recorded": {
            "ok": len(candidates) >= 1,
            "detail": f"{len(candidates)} candidate addresses from byte "
                      f"stores (planned callouts: "
                      f"{final.get('stats', {}).get('byteStoresPlanned')}, "
                      f"byte stores seen: "
                      f"{final.get('stats', {}).get('byteWrites')})",
        },
        "lic-copy-found": {
            "ok": lic_copy is not None,
            "detail": f"lic_copy={lic_copy} first bytes="
                      f"{final.get('licCopyFirstBytes')} (want {head_hex})",
        },
    }
    failed = [name for name, row in checks.items() if not row["ok"]]
    return {"checks": checks, "failed": failed, "ok": not failed,
            "status": "stage0-complete" if not failed else "failed"}


def judge_ci(run: dict, head_hex: str) -> dict:
    final = run.get("final", {})
    stats = final.get("stats", {})
    redirects = stats.get("redirects", 0)
    opens = stats.get("fileOpens", 0)
    mapped = bool(final.get("licenseMappedTo"))
    candidates = final.get("candidates") or []
    lic_copy = final.get("licCopy")
    checks = {
        "license-open-redirected": {
            "ok": redirects >= 1,
            "detail": f"{redirects} regkey.dat open(s) redirected of "
                      f"{opens} file opens seen; original path "
                      f"{final.get('originalLicensePath')}; opened: "
                      f"{(final.get('openedPaths') or [])[:5]}",
        },
        "license-mapped": {
            "ok": mapped,
            "detail": f"mapping at {final.get('licenseMappedTo')}",
        },
        "candidates-recorded": {
            "ok": len(candidates) >= 1,
            "detail": f"{len(candidates)} candidates from byte stores "
                      f"(byte stores seen: {stats.get('byteWrites')})",
        },
        "lic-copy-found": {
            "ok": lic_copy is not None,
            "detail": f"lic_copy={lic_copy}",
        },
    }
    stage1 = final.get("stage1") or {}
    stage1_events = [m.get("event") for m in (run.get("messages") or [])
                     if isinstance(m, dict) and m.get("spike") == "stage1"]
    hooked = stage1.get("hooked") or \
        sum(1 for e in stage1_events if e == "sub2-hooked")
    sub = stage1.get("sub") or 0
    # A landmark is proven by what followed it, not by the event name: the
    # event is windowed (first few landmarks only), so `hooked`/`sub` are the
    # authoritative signals.
    landmark = bool(stage1.get("landmark")) or \
        "sub1-landmark-module" in stage1_events or hooked > 0 or sub >= 2
    checks["stage1-rsa-chain"] = {
        "ok": stage1.get("complete") is True,
        "detail": f"sub-stage {stage1.get('sub')}, dec_sections="
                  f"{stage1.get('decSections')}, mp_exptmod="
                  f"{stage1.get('mpExptmod')}, calls="
                  f"{stage1.get('callCount')}, dec_lic="
                  f"{stage1.get('decLic')}, landmark={landmark}, "
                  f"sub2-hooked={hooked}, exits={final.get('exits')}, "
                  f"events={stage1_events[:12]}",
    }
    failed = [name for name, row in checks.items() if not row["ok"]]
    if stage1.get("complete"):
        status = "stage1-complete"
    elif hooked:
        status = "stage1-sub2"
    elif landmark:
        status = "stage1-landmark"
    elif lic_copy is not None:
        status = "stage0-complete"
    elif opens == 0:
        status = "inconclusive"
    else:
        status = "failed"
    return {"checks": checks, "failed": failed, "ok": not failed,
            "status": status}


def local_pass(opts, args) -> int:
    rows = []
    ok = True
    # The local run needs the same RSA key material as the CI run: sub-stage 4
    # fingerprints each call argument as an mp_int whose digit count is one of
    # the RSA component lengths, and with rsaKeys unset looksLikeKeyMpInt bails
    # immediately -- which reads in the report as "no key match" forever.
    rsa = Path(args.rsa)
    rsa_keys = None
    if rsa.exists():
        rsa_keys = read_rsa_keys(rsa)
        print(f"local rsa keys: mod1={rsa_keys['mod1Len']}d "
              f"exp1={rsa_keys['exp1Len']}d mod2={rsa_keys['mod2Len']}d "
              f"exp2={rsa_keys['exp2Len']}d", flush=True)
    else:
        print(f"WARNING: {rsa} missing -- the local run cannot exercise "
              f"sub-stage 4", flush=True)
    for opt in opts:
        binary = build_target(opt)
        workdir = BUILD / f"local_O{opt}"
        shutil.rmtree(workdir, ignore_errors=True)
        workdir.mkdir(parents=True, exist_ok=True)
        dummy = workdir / "regkey.dat"
        head_hex = make_dummy_license(dummy)
        print(f"\n=== local {sys.platform}/{ARCH} -O{opt} (head {head_hex}) ===",
              flush=True)
        run = run_agent(binary, workdir, head_hex, windows_nt_path(dummy),
                        args.duration, str(dummy), rsa_keys,
                        args.defer_tracing)
        verdict = judge_local(run, head_hex)
        run["verdict"] = verdict
        rows.append(run)
        print(f"  target: {run['target_stdout'].strip()}", flush=True)
        for name, check in verdict["checks"].items():
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"  [{mark}] {name}: {check['detail']}", flush=True)
        if not verdict["ok"]:
            ok = False
    out = RESULTS / f"spike2_local_{sys.platform}_{ARCH}.json"
    RESULTS.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {out}", flush=True)
    return 0 if ok else 1


def ci_pass(args) -> int:
    manifest_path = RESULTS / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit("results/manifest.json missing (run "
                         "scripts/prepare_samples.py first)")
    manifest = json.loads(manifest_path.read_text())
    by_label = {entry["label"]: entry for entry in manifest}
    rsa = Path(args.rsa)
    if not rsa.exists():
        print(f"WARNING: {rsa} missing -- Stage 1 cannot swap in real RSA "
              f"keys", flush=True)
        rsa_keys = None
    else:
        rsa_keys = read_rsa_keys(rsa)
        print(f"rsa keys: mod1={rsa_keys['mod1Len']}d exp1={rsa_keys['exp1Len']}d "
              f"mod2={rsa_keys['mod2Len']}d exp2={rsa_keys['exp2Len']}d",
              flush=True)
    dummy = Path(args.dummy)
    if not dummy.exists():
        # Stage 0 only cares about the license head, so a synthetic dummy
        # still exercises the whole redirect/map/copy/unmap path. Reported
        # loudly so a wl-lic build failure cannot hide behind it.
        print(f"WARNING: {dummy} missing (wl-lic build failed?) -- falling "
              f"back to a synthetic dummy license", flush=True)
        dummy.parent.mkdir(parents=True, exist_ok=True)
        make_dummy_license(dummy)
    head_hex = dummy.read_bytes()[:HEAD_LEN].hex()
    nt_path = windows_nt_path(dummy)
    print(f"dummy license: {dummy} head={head_hex} nt={nt_path}", flush=True)

    rows = []
    for label in [t.strip() for t in args.targets.split(",") if t.strip()]:
        entry = by_label.get(label)
        if entry is None or not entry.get("pes"):
            print(f"--- {label}: no PE in the manifest, skipped", flush=True)
            rows.append({"label": label, "error": "no PE in manifest"})
            continue
        target = None
        # Prefer a real executable: some archives ship a helper DLL as their
        # first x64 PE and frida cannot spawn a DLL ("unsupported file
        # format", as test84's fmodex64.dll did).
        for pe in sorted(entry["pes"],
                         key=lambda p: 0 if p["path"].lower().endswith(".exe")
                         else 1):
            if pe["arch"] == ARCH:
                target = pe
                break
        if target is None:
            print(f"--- {label}: no {ARCH} PE (have "
                  f"{[p['arch'] for p in entry['pes']]}), skipped",
                  flush=True)
            rows.append({"label": label, "error": f"no {ARCH} PE"})
            continue
        exe = (ROOT / target["path"]).resolve()
        workdir = exe.parent
        # Repeats exist because the single real-target Stage 1 landmark seen so
        # far did not reproduce: one observation is not a result, and a hit
        # rate is what says whether the guard/landmark race is real or whether
        # the one hit was process-teardown noise.
        for attempt in range(1, args.repeat + 1):
            tag = label if args.repeat == 1 else f"{label}#{attempt}"
            print(f"\n=== {tag}: {exe.name} (v{target['version']}) ===",
                  flush=True)
            try:
                run = run_agent(exe, workdir, head_hex, nt_path, args.duration,
                                str(dummy), rsa_keys, args.defer_tracing)
                verdict = judge_ci(run, head_hex)
            except Exception as exc:  # noqa: BLE001
                # One sample refusing to inject must not take the whole leg
                # down (it did once: ragexe raised ProcessNotRespondingError
                # and no results were written at all).
                import traceback
                print(f"  runner exception: {exc}", flush=True)
                rows.append({"label": tag, "error": str(exc),
                             "traceback": traceback.format_exc()})
                continue
            run["label"] = tag
            run["verdict"] = verdict
            rows.append(run)
            print(f"  target: {run['target_stdout'].strip()[:300]}", flush=True)
            for name, check in verdict["checks"].items():
                mark = "PASS" if check["ok"] else "FAIL"
                print(f"  [{mark}] {name}: {check['detail']}", flush=True)
            print(f"  -> {verdict['status']}", flush=True)

    RESULTS.mkdir(exist_ok=True)
    suffix = "_deferred" if args.defer_tracing else ""
    out = RESULTS / f"spike2_ci_{sys.platform}_{ARCH}{suffix}.json"
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {out}", flush=True)

    summary = ["## Spike 2 — Stage 0 (license copy location)"
               + (" (deferred tracing)" if args.defer_tracing else ""), ""]
    for row in rows:
        if row.get("error"):
            summary.append(f"- `{row['label']}`: {row['error']}")
            continue
        verdict = row.get("verdict", {})
        summary.append(f"- `{row['label']}`: {verdict.get('status')} "
                       f"({'; '.join(f'{k}={v}' for k, v in verdict.get('checks', {}).items())})")
    summary.append("")
    gh_sum = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_sum:
        with open(gh_sum, "a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")

    completed = [r for r in rows
                 if r.get("verdict", {}).get("status") in
                 ("stage0-complete", "stage1-landmark", "stage1-sub2",
                  "stage1-complete")]
    return 0 if completed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--opts", default="0,2")
    parser.add_argument("--duration", type=int, default=150)
    parser.add_argument("--dummy", default="")
    parser.add_argument("--rsa", default="results/spike2_dummy/regkey.rsa")
    parser.add_argument("--targets", default="")
    parser.add_argument("--defer-tracing", action="store_true",
                        help="do not follow threads at startup; let the "
                             "MapViewOfFile hook start the trace, so the "
                             "protection's own unpacking runs at native speed")
    parser.add_argument("--repeat", type=int, default=1,
                        help="run each target N times (a single observation of "
                             "a flaky landmark is not a result)")
    args = parser.parse_args()

    RESULTS.mkdir(exist_ok=True)
    if args.local:
        return local_pass([int(o) for o in args.opts.split(",")], args)
    if args.ci:
        return ci_pass(args)
    raise SystemExit("pick --local or --ci")


if __name__ == "__main__":
    sys.exit(main())
