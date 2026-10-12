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
from pathlib import Path
from typing import Any, Dict, Optional

import frida
import frida.core

LOG = logging.getLogger(__name__)

# The agent compares this many leading bytes of the mapped licence.
HEAD_LEN = 8

# Where the agent lives.  It is the same file the spike2 harness loads, so the
# two cannot drift apart.
_AGENT_NAME = "spike2_agent.js"


def guard_enabled() -> bool:
    return os.environ.get("UNLICENSE_GUARD") == "1"


def _agent_source() -> str:
    """Read the guard agent, from the package resources if present."""
    try:
        from importlib import resources
        return resources.open_text("unlicense.resources", _AGENT_NAME).read()
    except (FileNotFoundError, ModuleNotFoundError):
        pass
    # Fall back to the checkout: this is a research tree, not a wheel.
    path = Path(__file__).resolve().parent.parent / "spikes" / _AGENT_NAME
    if not path.is_file():
        raise FileNotFoundError(
            f"guard agent not found: tried package resource {_AGENT_NAME!r} "
            f"and {path}")
    return path.read_text()


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
    lengths = {"mod1": data[0], "exp1": data[1], "mod2": data[2],
               "exp2": data[3]}
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
        LOG.info("guard %s %s", spike,
                 json.dumps(payload, default=str)[:400])


def install(session: frida.core.Session, pe_path: Path) -> Optional[Any]:
    """Load the guard agent into an existing session.

    Returns the script so the caller can arm tracing after resuming, or ``None``
    when the guard is disabled or has nothing to work with.
    """
    if not guard_enabled():
        return None
    licence = find_license_file(pe_path)
    if licence is None:
        LOG.warning("UNLICENSE_GUARD=1 but no licence file found next to %s; "
                    "the protection will reject the run", pe_path.name)
        return None
    try:
        head_hex = licence.read_bytes()[:HEAD_LEN].hex()
    except OSError as exc:
        LOG.warning("guard: cannot read %s: %s", licence, exc)
        return None
    rsa_keys = find_rsa_keys(pe_path)
    if rsa_keys is None:
        # Without our keys Stage 1 has nothing to swap in, and the protection
        # keeps its own -- which will reject our licence.  Say so rather than
        # producing an rc=4 that looks like a timeout.
        LOG.warning("guard: no RSA keys (UNLICENSE_GUARD_RSA or a sibling "
                    "regkey.rsa); Stage 1 cannot replace the embedded keys")
    script = session.create_script(_agent_source())
    script.on("message", _on_message)
    script.load()
    script.exports_sync.setup({
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
    })
    LOG.info("guard agent armed: licence=%s head=%s rsaKeys=%s",
             licence, head_hex, rsa_keys is not None)
    return script


def start_tracing(script: Any) -> None:
    """Arm Stalker once the process is running.  Never raises."""
    if script is None:
        return
    try:
        result = script.exports_sync.start_tracing()
        LOG.info("guard tracing: %s", result)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("guard: start_tracing failed: %s", exc)
