"""Neutralize a WinLicense/Themida licence check in the process being unpacked.

The unpacker's own flow spawns the target, attaches Frida, loads ``frida.js``
(which finds the OEP) and resumes.  On a real protected sample that is not
enough: the protection refuses to let the unpacked image run while the licence is
rejected, so the OEP never fires and the run dies with ``rc=4`` (OEP timeout).
See ``unlicense-handoff.md`` sections 9.29 and 9.48.

The guard agent (``spikes/hwbreak_agent.js`` plus ``spikes/spike2_agent.js``)
does the neutralizing:

* Stage 0 recovers ``lic_copy`` -- where the protection copies the mapped
  licence.
* Stage 1 swaps the RSA keys the protection embedded for ours, so its decrypt
  produces a plaintext it accepts.
* Stage 2 neutralizes the ``hash_3`` comparison that would otherwise reject the
  decrypted licence.

All three have to run in the same process as the OEP tracing: the licence must be
accepted for the OEP to be reached at all, so a separate run cannot help.

**One script, one exception handler.**  ``frida.js`` needs
``Process.setExceptionHandler`` to find the OEP, and the guard needs it because
its whole mechanism is PAGE_GUARD faults.  A Frida script has exactly one
handler, so installing the guard's would silently disable OEP detection and
installing ``frida.js``'s would silently disarm the guard -- ``frida.js``
un-protects every non-execute faulting page and returns true, so the guard would
never see its own fault.  This module therefore concatenates the guard modules
and ``frida.js`` into a single source, merges their ``rpc.exports``, and installs
one handler that asks the guard first and falls through to the OEP handler.

Enabled by ``UNLICENSE_GUARD=1``.  Without it none of this is used and the
existing flow is unchanged.
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import frida
import frida.core

LOG = logging.getLogger(__name__)

# The agent compares this many leading bytes of the mapped licence.
HEAD_LEN = 8

# The guard is more than one file.  Frida evaluates a single source string, so
# the helper module must be inlined ahead of the main agent -- the same order
# spikes/run_spike2.py uses.  spike2_agent.js calls hwBreakOnException, which
# hwbreak_agent.js defines; loading spike2_agent.js alone left the identifier
# undefined and the exception handler threw ReferenceError on its first
# exception, so neither Stage 1's guard-page path nor Stage 2's guard ever ran:
#   guard stage1 exception-handler-error ReferenceError: 'hwBreakOnException' is not defined
_GUARD_MODULES = ("hwbreak_agent.js", "spike2_agent.js")

# How the two halves install their exception handlers, and how the guard declares
# its exports.  Rewriting these at load time is what lets one script host both.
_GUARD_HANDLER_CALL = "Process.setExceptionHandler(function (details) {"
_FRIDA_HANDLER_CALL = "Process.setExceptionHandler(exp => {"
_GUARD_EXPORTS = "rpc.exports = {"

# Appended after both halves are evaluated: one handler, and one exports object.
_MERGE_TAIL = """
/* One handler for both halves, and one exports object.
 *
 * A Frida script has a single exception handler, so the second
 * Process.setExceptionHandler call replaces the first: the guard would be
 * disarmed by frida.js (which un-protects every non-execute faulting page and
 * returns true) or OEP detection would be disabled by the guard. Keep both
 * callbacks and call the guard's first -- it only claims faults inside its own
 * guarded ranges.
 */
(function () {
    const __fridaExports = rpc.exports || {};
    rpc.exports = Object.assign({}, __fridaExports, __guardRpc, {
        install_exception_handler: function () {
            Process.setExceptionHandler(function (details) {
                try {
                    if (__guardExceptionHandler !== undefined &&
                        __guardExceptionHandler(details)) {
                        return true;
                    }
                } catch (e) {
                    /* fall through to the OEP handler rather than losing the
                     * exception entirely */
                }
                try {
                    return __fridaExceptionHandler !== undefined
                        ? __fridaExceptionHandler(details) : false;
                } catch (e) {
                    return false;
                }
            });
            return true;
        }
    });
})();
"""


def guard_enabled() -> bool:
    return os.environ.get("UNLICENSE_GUARD") == "1"


def _say(message: str) -> None:
    """Report on stdout as well as through logging.

    The first guarded unpack run produced no guard output at all and died on the
    300s hard kill with rc=-1, so there was no way to tell whether the agent was
    installed, hung, or never loaded. Logging alone was not enough: the level in
    that run did not surface it. Say it plainly.
    """
    LOG.info("%s", message)
    print("license_guard: " + message, flush=True)


def _rpc_with_timeout(call: Callable[[], Any], seconds: float,
                      what: str) -> Any:
    """Run an RPC with a deadline.

    A deadlocked agent makes an RPC block forever -- spikes/run_spike2.py wraps
    every call for exactly this reason. Without a deadline here the unpacker hung
    until the runner's hard kill, which is what rc=-1 330.1s means.
    """
    box: Dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = call()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise TimeoutError(f"{what} did not return within {seconds}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _search_dirs() -> List[Path]:
    """Where to look for the agent modules, most specific first.

    The first guarded CI run died with FileNotFoundError because the package is
    installed into site-packages, where ``Path(__file__).parent.parent`` has no
    ``spikes/`` beside it; UNLICENSE_GUARD_AGENT (set by run_unpack.py) is
    honoured first for that reason.
    """
    dirs = []
    override = os.environ.get("UNLICENSE_GUARD_AGENT")
    if override:
        dirs.append(Path(override).resolve().parent)
    # Installed package (poetry ships files that live inside the package).
    dirs.append(Path(__file__).resolve().parent / "resources")
    # A checkout: this is a research tree, not always a wheel.
    dirs.append(Path(__file__).resolve().parent.parent / "spikes")
    return dirs


def _read_module(name: str) -> str:
    dirs = _search_dirs()
    for directory in dirs:
        candidate = directory / name
        if candidate.is_file():
            return candidate.read_text()
    raise FileNotFoundError(f"agent module {name!r} not found in "
                            f"{[str(d) for d in dirs]}")


def combined_source() -> str:
    """One script source: guard modules, then frida.js, then the merge tail.

    The guard's modules come first because spike2_agent.js calls
    hwBreakOnException, which hwbreak_agent.js defines. frida.js follows so its
    ``rpc.exports`` assignment happens before the tail merges the two.
    """
    guard = "\n".join(_read_module(name) for name in _GUARD_MODULES)
    if _GUARD_HANDLER_CALL not in guard:
        raise ValueError("guard agent: exception handler call not found; the "
                         "merge would leave the guard disarmed")
    if _GUARD_EXPORTS not in guard:
        raise ValueError("guard agent: rpc.exports not found")
    guard = guard.replace(_GUARD_HANDLER_CALL,
                          "__guardExceptionHandler = function (details) {", 1)
    guard = guard.replace(_GUARD_EXPORTS, "const __guardRpc = {", 1)
    frida = _read_module("frida.js")
    if _FRIDA_HANDLER_CALL not in frida:
        raise ValueError(
            "frida.js: exception handler call not found; the merge "
            "would leave OEP detection disabled")
    frida = frida.replace(_FRIDA_HANDLER_CALL,
                          "__fridaExceptionHandler = exp => {", 1)
    return "\n".join([guard, frida, _MERGE_TAIL])


def message_handler(
    on_oep_reached: Callable[[Dict[str, Any]], None]
) -> Callable[[Dict[str, Any], Any], None]:
    """Dispatch both halves' messages.  Never raises on an unknown message.

    ``frida_exec._frida_callback`` raises NotImplementedError for anything it
    does not recognise, which a merged script would trip on the first guard
    event.
    """

    def handler(message: Dict[str, Any], _data: Any) -> None:
        kind = message.get("type")
        if kind == "error":
            LOG.error("agent error: %s", message.get("description"))
            LOG.debug("%s", message.get("stack"))
            return
        if kind != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("event") == "oep_reached":
            on_oep_reached(payload)
            return
        spike = payload.get("spike")
        if spike in ("stage1", "stage2"):
            LOG.info("guard %s %s %s", spike, payload.get("event"),
                     payload.get("detail"))
        elif spike:
            LOG.info("guard %s %s", spike,
                     json.dumps(payload, default=str)[:400])

    return handler


def find_license_file(pe_path: Path) -> Optional[Path]:
    """Locate the licence the protection will read.

    ``UNLICENSE_GUARD_LICENSE`` wins.  Otherwise look next to the executable: a
    ``regkey.dat`` (what WinLicense itself reads) or a lone ``*.lic``.
    """
    override = os.environ.get("UNLICENSE_GUARD_LICENSE")
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    directory = pe_path.parent
    for name in ("regkey.dat", "license.lic"):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    licences = sorted(directory.glob("*.lic"))
    if len(licences) == 1:
        return licences[0]
    return None


def _read_rsa_keys(path: Path) -> Optional[Dict[str, Any]]:
    """Parse ``wl-lic``'s RSA output: four length bytes, then the digit arrays.

    ``mp_digit`` is 32-bit on the 32-bit target, so a length of n digits is n*4
    bytes.  Same format ``spikes/run_spike2.py`` reads.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 4:
        return None
    lengths = {
        "mod1": data[0],
        "exp1": data[1],
        "mod2": data[2],
        "exp2": data[3]
    }
    offset = 4
    keys: Dict[str, Any] = {}
    for name, length in lengths.items():
        chunk = data[offset:offset + length * 4]
        offset += length * 4
        if len(chunk) != length * 4:
            return None
        keys[name] = chunk.hex()
        keys[name + "Len"] = length
    return keys


def find_rsa_keys(pe_path: Path) -> Optional[Dict[str, Any]]:
    """Our replacement RSA keys, if the user produced any with wl-lic."""
    override = os.environ.get("UNLICENSE_GUARD_RSA")
    if override:
        candidate = Path(override)
        return _read_rsa_keys(candidate) if candidate.is_file() else None
    candidate = pe_path.parent / "regkey.rsa"
    if candidate.is_file():
        return _read_rsa_keys(candidate)
    return None


def _windows_nt_path(path: Path) -> str:
    absolute = str(path.resolve())
    if not absolute.startswith("\\\\"):
        return "\\??\\" + absolute
    return absolute


def arm(script: frida.core.Script, pe_path: Path) -> bool:
    """Point the guard at the licence, start it, install the handler.

    Never raises.  Returns True when the guard is armed; any failure leaves the
    run behaving as it did before the guard existed -- an OEP timeout at worst --
    rather than hanging until the runner's hard kill.
    """
    licence = find_license_file(pe_path)
    if licence is None:
        _say("no licence file found; the protection will reject the run")
        return False
    try:
        head_hex = licence.read_bytes()[:HEAD_LEN].hex()
    except OSError as exc:
        _say(f"cannot read {licence}: {exc}")
        return False
    rsa_keys = find_rsa_keys(pe_path)
    # No keys is not an error while identityKey is on: the agent then builds its
    # own (exponent 1), which is what makes the decrypt the identity. The CI
    # spike2 runs show exactly that (keys-materialised ... identityKey=true with
    # no regkey.rsa present).
    _say(f"arming: licence={licence} head={head_hex}")
    try:
        _rpc_with_timeout(
            lambda: script.exports_sync.
            setup({
                "headHex": head_hex,
                "ntPath": _windows_nt_path(licence),
                "licenseFile": str(licence),
                "licSize": licence.stat().st_size,
                "rsaKeys": rsa_keys,
                # The protection unpacks at native speed unless tracing is deferred.
                "deferTracing": True,
                # A real sample calls the RSA routine once; whatlicense's model needs
                # dec_sections + 1.
                "stage1CompleteAfter": 1,
                # An exponent of 1 makes the protection's decrypt the identity, so the
                # decrypted buffer is the licence blob itself instead of a lottery.
                "identityKey": True,
                "guardSpan": 0x4000,
            }),
            60.0,
            "guard setup")
        # Only now: setup() is what assigns the guard's callback, and the combined
        # handler has to be installed after both halves exist.
        _rpc_with_timeout(
            lambda: script.exports_sync.install_exception_handler(), 30.0,
            "install_exception_handler")
    except Exception as exc:  # noqa: BLE001
        _say(f"guard setup failed ({exc}); continuing without it")
        return False
    _say("armed (one script, one exception handler)")
    return True


def start_tracing(script: Optional[frida.core.Script]) -> None:
    """Arm Stalker once the process is running.  Never raises, never blocks."""
    if script is None:
        return
    try:
        result = _rpc_with_timeout(lambda: script.exports_sync.start_tracing(),
                                   30.0, "guard start_tracing")
        _say(f"tracing: {result}")
    except Exception as exc:  # noqa: BLE001
        _say(f"start_tracing failed: {exc}")
