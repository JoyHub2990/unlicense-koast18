#!/usr/bin/env python3
"""Add a Pin 3.27+|x64 configuration to whatlicense's wl-extract.vcxproj.

Why this exists
---------------
`pin.yml` builds the **top-level** `whatlicense/wl-extract.vcxproj`, and that
project declares only `Pin 3.26|Win32` and `Pin 3.27+|Win32`. Building it with
`/p:Platform=x64` therefore fails with MSB8013 ("This project doesn't contain the
Configuration and Platform combination"), which is why the x64 attempt produced
wl-lic.exe and nothing else.

The three WinLicense samples in crypt.zip are x64, so wl-extract has to be x64 to
instrument them -- and that matters because wl-extract's Stage 5 is what produces a
main_hash belonging to *that* protection. Without it the license keeps the
randomized hash_3 that `wl-lic` writes by default (crypt.cpp:
main_hash_key::randomize), which the protection must reject: wl-lic says so itself
("main_hash unspecified -- Building dummy license for use during extraction").

What it does
------------
Duplicates each `Pin 3.27+|Win32` block as `Pin 3.27+|x64`, substituting the x64
toolchain's paths and defines:

    ..\\..\\..\\ia32\\        -> ..\\..\\..\\intel64\\
    TARGET_IA32;HOST_IA32  -> TARGET_IA32E;HOST_IA32E
    __i386__               -> _WIN64

The substitutions are the mechanical part of the port; whether the C++ itself
carries IA-32 assumptions is what the build then tells us.
"""

import re
import sys
from pathlib import Path

WIN32 = "Pin 3.27+|Win32"
X64 = "Pin 3.27+|x64"

# Quoting note: the project spells its conditions with both quote characters
# (Condition="'$(Configuration)|$(Platform)'=='Pin 3.27+|Win32'"). Writing that in
# a Python raw string is a trap -- in a raw string \" is a backslash followed by a
# quote, so the pattern demanded a literal backslash and matched nothing. Build the
# quotes from chr(34)/chr(39) instead.
Q = chr(34)
SQ = chr(39)

# The condition exactly as the project writes it.
COND = SQ + "$(Configuration)|$(Platform)" + SQ + "==" + SQ + WIN32 + SQ


def to_x64(block: str) -> str:
    out = block.replace(WIN32, X64)
    out = out.replace("..\\..\\..\\ia32\\", "..\\..\\..\\intel64\\")
    out = out.replace("TARGET_IA32;HOST_IA32", "TARGET_IA32E;HOST_IA32E")
    out = out.replace("__i386__", "_WIN64")
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: inject_pin_x64.py <wl-extract.vcxproj>")
        return 2
    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8", errors="replace")

    if X64 in text:
        print("already has the x64 configuration")
        return 0

    # 1. The ProjectConfigurations entry.
    anchor = ("    <ProjectConfiguration Include=" + Q + WIN32 + Q + ">\n"
              "      <Configuration>Pin 3.27+</Configuration>\n"
              "      <Platform>Win32</Platform>\n"
              "    </ProjectConfiguration>\n")
    if anchor not in text:
        print("ProjectConfigurations entry not found")
        return 1
    text = text.replace(anchor, anchor + to_x64(anchor), 1)

    # 2. Every block conditioned on the Win32 configuration: the PropertyGroup,
    #    the ImportGroup and the ItemDefinitionGroup.
    opener = ("(<(PropertyGroup|ImportGroup|ItemDefinitionGroup) Condition=" + Q +
              re.escape(COND) + Q + "[^>]*>)")
    pattern = re.compile(opener + "(.*?)(</\\2>\\n)", re.S)

    count = 0

    def add(match: "re.Match") -> str:
        nonlocal count
        count += 1
        whole = match.group(0)
        return whole + to_x64(whole)

    text = pattern.sub(add, text)
    if count == 0:
        print("no Win32 blocks matched")
        return 1

    path.write_text(text, encoding="utf-8")
    print("added %s (%d blocks duplicated)" % (X64, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
