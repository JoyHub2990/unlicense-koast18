"""Neutralize a WinLicense/Themida licence check in the process being unpacked.

The unpacker's own flow spawns the target, attaches Frida, loads ``frida.js``
(which finds the OEP) and resumes.  On a real protected sample that is not
enough: the protection refuses to let the unpacked image run while the licence is
rejected, so the OEP never fires and the run dies with ``rc=4`` (OEP timeout).
See ``unlicense-handoff.md`` sections 9.29 and 9.48.

This module loads the agent the ``spikes/spike2_agent.js`` harness uses into the
*same* Frida session, before the process is resumed:

* Stage 0 recovers ``lic_copy`` -- where the protection copies the mapped
  licence.
* Stage 1 swaps the RSA keys the protection embedded for ours, so its decrypt
  produces a plaintext it accepts.
* Stage 2 neutralizes the ``hash_3`` comparison that would otherwise reject the
  decrypted licence.

All three have to run in the same process as the OEP tracing: the licence must be
accepted for the OEP to be reached at all, so a separate run cannot help.

Enabled by ``UNLICENSE_GUARD=1``.  Without it this module does nothing and the
existing flow is byte-for-byte unchanged.
"""

import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import frida
import frida.core

LOG = logging.getLogger(__name__)


def _say(message: str) -> None:
    """Report on stdout as well as through logging.

    The first guarded unpack run produced no guard output at all and died on the
    300s hard kill with rc=-1, so there was no way to tell whether the agent was
    installed, hung, or never loaded. Logging alone was not enough: the level in
    that run did not surface it. Say it plainly.
    """
    LOG.info("%s", message)
    print("license_guard: " + message, flush=True)


def _rpc_with_timeout(call: Any, seconds: float, what: str) -> Any:
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


# The agent compares this many leading bytes of the mapped licence.
HEAD_LEN = 8

# Where the agent lives.  It is the same file the spike2 harness loads, so the
# two cannot drift apart.
_AGENT_NAME = "spike2_agent.js"

# The agent is not one file.  Frida evaluates a single source string, so the
# helper module is inlined ahead of the main agent -- the same order
# spikes/run_spike2.py uses.  spike2_agent.js calls hwBreakOnException, which
# hwbreak_agent.js defines; loading spike2_agent.js alone left the identifier
# undefined and the exception handler threw ReferenceError on its first
# exception, so Stage 1's guard-page path and Stage 2's guard never ran. The
# guarded CI run said so exactly:
#   guard stage1 exception-handler-error ReferenceError: 'hwBreakOnException' is not defined
_AGENT_MODULES = ("hwbreak_agent.js", "spike2_agent.js")


def guard_enabled() -> bool:
    return os.environ.get("UNLICENSE_GUARD") == "1"


def _agent_dirs() -> "list[Path]":
    """Where to look for the agent modules, most specific first."""
    dirs = []
    override = os.environ.get("UNLICENSE_GUARD_AGENT")
    if override:
        dirs.append(Path(override).resolve().parent)
    # Installed package (poetry ships files that live inside the package).
    dirs.append(Path(__file__).resolve().parent / "resources")
    # A checkout: this is a research tree, not always a wheel.
    dirs.append(Path(__file__).resolve().parent.parent / "spikes")
    return dirs


def _agent_source() -> str:
    """Concatenate the agent modules into one script.

    The first guarded CI run died with FileNotFoundError because the package is
    installed into site-packages, where ``Path(__file__).parent.parent`` has no
    ``spikes/`` beside it; UNLICENSE_GUARD_AGENT (set by run_unpack.py) is
    honoured first for that reason.
    """
    dirs = _agent_dirs()
    parts = []
    for name in _AGENT_MODULES:
        for directory in dirs:
            candidate = directory / name
            if candidate.is_file():
                parts.append(candidate.read_text())
                break
        else:
            raise FileNotFoundError(
                f"guard agent module {name!r} not found in "
                f"{[str(d) for d in dirs]}")
    return "\n".join(parts)


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


def _on_message(message: Dict[str, Any], _data: Any) -> None:
    if message.get("type") == "error":
        LOG.error("guard agent error: %s", message.get("description"))
        LOG.debug("%s", message.get("stack"))
        return
    if message.get("type") != "send":
        return
    payload = message.get("payload") or {}
    spike = payload.get("spike")
    if spike in ("stage1", "stage2"):
        LOG.info("guard %s %s %s", spike, payload.get("event"),
                 payload.get("detail"))
    elif spike:
        LOG.info("guard %s %s", spike, json.dumps(payload, default=str)[:400])


def install(session: frida.core.Session, pe_path: Path) -> Optional[Any]:
    """Load the guard agent into an existing session.

    Returns the script so the caller can arm tracing after resuming, or ``None``
    when the guard is disabled or has nothing to work with.
    """
    if not guard_enabled():
        return None
    _say(f"enabled; looking for a licence next to {pe_path.name}")
    licence = find_license_file(pe_path)
    if licence is None:
        _say("no licence file found; the protection will reject the run")
        return None
    try:
        head_hex = licence.read_bytes()[:HEAD_LEN].hex()
    except OSError as exc:
        _say(f"cannot read {licence}: {exc}")
        return None
    rsa_keys = find_rsa_keys(pe_path)
    # No keys is not an error while identityKey is on: the agent then builds its
    # own (exponent 1), which is what makes the decrypt the identity. The CI
    # spike2 runs show exactly that (keys-materialised ... identityKey=true with
    # no regkey.rsa present), so warning about it here only misleads.
    source = _agent_source()
    _say(f"loading agent ({len(source)} bytes)")

    def _load() -> Any:
        created = session.create_script(source)
        created.on("message", _on_message)
        created.load()
        return created

    # Bounded, and non-fatal: if the agent cannot be loaded the run should behave
    # exactly as it did before the guard existed (an OEP timeout at worst), not
    # hang until the runner's hard kill.
    try:
        script = _rpc_with_timeout(_load, 90.0, "guard script load")
    except Exception as exc:  # noqa: BLE001
        _say(f"could not load the guard agent ({exc}); continuing without it")
        return None
    _say("agent loaded; calling setup")
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
    except Exception as exc:  # noqa: BLE001
        _say(f"guard setup failed ({exc}); continuing without it")
        return None
    _say(f"armed: licence={licence} head={head_hex} "
         f"rsaKeys={'yes' if rsa_keys else 'no'}")
    return script


def start_tracing(script: Any) -> None:
    """Arm Stalker once the process is running.  Never raises, never blocks."""
    if script is None:
        return
    try:
        result = _rpc_with_timeout(lambda: script.exports_sync.start_tracing(),
                                   30.0, "guard start_tracing")
        _say(f"tracing: {result}")
    except Exception as exc:  # noqa: BLE001
        _say(f"start_tracing failed: {exc}")
