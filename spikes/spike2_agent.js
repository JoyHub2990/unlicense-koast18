"use strict";

/*
 * Spike 2 agent — Stage 0 of the whatlicense pipeline, ported from the PIN
 * tool (`wl-extract/main.cpp`, Stage 0) to the Frida stack.
 *
 * Stage 0 recovers `lic_copy`: where the protection copies the mapped
 * license file to. The PIN original:
 *
 *   1. NtCreateFile/ZwCreateFile hook: an open whose path ends in
 *      "regkey.dat" is redirected to our (dummy) license file, and the
 *      opening thread is remembered as the main thread.
 *   2. MapViewOfFile hook: after the real call, if the first 8 bytes of the
 *      mapping equal the license file's first 8 bytes -> lic_mapped.
 *   3. While lic_mapped: every 1-byte write to memory on the main thread
 *      whose value equals the license head byte records its effective
 *      address as a candidate (PIN inserts this at IPOINT_AFTER, i.e. it
 *      reads the byte just written).
 *   4. UnmapViewOfFile hook: when the unmap target's first 8 bytes are the
 *      license head, search the candidates for one whose first 8 bytes now
 *      match -> that address is lic_copy.
 *
 * Frida differences that shaped this port:
 *   - A Stalker callout runs BEFORE the instruction, so the PIN trick of
 *     reading the just-written byte is impossible. Instead the byte about to
 *     be written is derived from the store's source operand (register or
 *     immediate), which yields the same candidate set.
 *   - MapViewOfFile/UnmapViewOfFile are Interceptor.attach hooks on the
 *     exports (no need to reimplement the call like PIN's
 *     RTN_ReplaceSignature).
 *   - Linux has no NtCreateFile; the same logic is exercised there through
 *     mmap/munmap (the local target opens the file itself), which is what
 *     makes this spike testable in seconds instead of only in CI.
 */

const HEAD_LEN = 8;

let plan = null;
let report = null;
let stats = null;
let followStart = 0;

const IS_WINDOWS = Process.platform === "windows";
const PTR_SIZE = Process.pointerSize;
const IS_IA32 = Process.arch === "ia32";
const PC_REG = IS_IA32 ? "eip" : "rip";
const SP_REG = IS_IA32 ? "esp" : "rsp";
const BP_REG = IS_IA32 ? "ebp" : "rbp";

function log(message) {
    console.log("spike2: " + message);
}

function threadStates() {
    /* A frozen byte-store counter can mean "blocked" or "running elsewhere";
     * the per-thread state separates them. */
    try {
        return Process.enumerateThreads().map(function (t) {
            return t.id + ":" + (t.state || "?");
        }).join(" ");
    } catch (e) {
        return "";
    }
}

function emit(payload) {
    try {
        send(payload);
    } catch (e) {
        /* console output from a callout is not reliable; send() is */
    }
}

function hex(bytes) {
    const out = [];
    for (let i = 0; i < bytes.length; i++) {
        out.push(bytes[i].toString(16).padStart(2, "0"));
    }
    return out.join("");
}

function headMatches(pointer) {
    if (pointer === null || pointer.isNull()) {
        return false;
    }
    try {
        const bytes = new Uint8Array(pointer.readByteArray(HEAD_LEN));
        for (let i = 0; i < HEAD_LEN; i++) {
            if (bytes[i] !== plan.head[i]) {
                return false;
            }
        }
        return true;
    } catch (e) {
        return false;
    }
}

/* The byte a 1-byte store is about to write, from its source operand. */
const BYTE_REGISTERS = {
    al: ["eax", 0], cl: ["ecx", 0], dl: ["edx", 0], bl: ["ebx", 0],
    ah: ["eax", 8], ch: ["ecx", 8], dh: ["edx", 8], bh: ["ebx", 8],
    spl: ["esp", 0], bpl: ["ebp", 0], sil: ["esi", 0], dil: ["edi", 0],
    r8b: ["r8", 0], r9b: ["r9", 0], r10b: ["r10", 0], r11b: ["r11", 0],
    r12b: ["r12", 0], r13b: ["r13", 0], r14b: ["r14", 0], r15b: ["r15", 0]
};

function wideName(context, name) {
    if (context[name] !== undefined) {
        return name;
    }
    const wide = {
        eax: "rax", ebx: "rbx", ecx: "rcx", edx: "rdx",
        esi: "rsi", edi: "rdi", ebp: "rbp", esp: "rsp"
    }[name];
    if (wide !== undefined && context[wide] !== undefined) {
        return wide;
    }
    return name;
}

function writtenByte(info, context) {
    /* The store's value operand: operands[0] is the memory destination. */
    for (let i = 1; i < info.operands.length; i++) {
        const operand = info.operands[i];
        if (operand.type === "imm") {
            return operand.value & 0xff;
        }
        if (operand.type === "mem") {
            /* A memory-source 1-byte store (movs / a memcpy loop). The byte
             * that will be written is the byte at the source EA right now, so
             * read it here -- before the instruction executes. */
            try {
                const source = computeEA(operand.value, context, info.next);
                stats.byteWritesFromMem++;
                return source.readU8();
            } catch (e) {
                return null;
            }
        }
        if (operand.type === "reg") {
            const entry = BYTE_REGISTERS[operand.value];
            if (entry === undefined) {
                return null; /* 32/64-bit source with a 1-byte dest: unusual */
            }
            const name = wideName(context, entry[0]);
            if (context[name] === undefined) {
                return null;
            }
            const value = context[name].toUInt32();
            return (value >>> entry[1]) & 0xff;
        }
    }
    return null;
}

function snapshot(insn) {
    const info = {
        address: insn.address.toString(),
        mnemonic: insn.mnemonic,
        opStr: insn.opStr,
        size: insn.size,
        next: insn.address.add(insn.size).toString(),
        operands: [],
        mem: null
    };
    for (const operand of insn.operands) {
        const entry = { type: operand.type, size: operand.size };
        if (operand.type === "mem") {
            const value = operand.value;
            entry.value = {
                base: value.base,
                index: value.index,
                scale: value.scale,
                disp: value.disp
            };
            info.mem = entry.value;
        } else if (operand.type === "imm") {
            entry.value = operand.value >>> 0;
        } else {
            entry.value = String(operand.value);
        }
        info.operands.push(entry);
    }
    return info;
}

function computeEA(mem, context, nextAddress) {
    let ea = ptr(0);
    if (mem.base === "rip" || mem.base === "eip") {
        ea = ea.add(ptr(nextAddress));
    } else if (mem.base !== undefined) {
        ea = ea.add(context[mem.base]);
    }
    if (mem.index !== undefined) {
        ea = ea.add(context[mem.index].mul(mem.scale || 1));
    }
    if (mem.disp !== undefined) {
        ea = ea.add(mem.disp);
    }
    return ea;
}

/* Called for every 1-byte memory store outside a system module. Every early
 * return gets its own counter: a single "candidates == 0" cannot tell "the
 * license was never mapped" from "the source byte could not be resolved" from
 * "the thread filter rejected it", and those need completely different fixes.
 * (Same lesson as stage1CallCandidate's silent return, which cost two CI
 * rounds.) */
function recordCandidate(info, context) {
    stats.byteWrites++;
    if (!plan.licMapped) {
        stats.rwNoMap++;
        return;
    }
    let tid = null;
    try {
        tid = Process.getCurrentThreadId();
    } catch (e) {
        stats.rwNoTid++;
        return;
    }
    if (plan.mainThread !== null && tid !== plan.mainThread) {
        stats.rwNoTid++;
        return;
    }
    let byte = null;
    try {
        byte = writtenByte(info, context);
    } catch (e) {
        byte = null;
    }
    if (byte === null || byte === undefined) {
        stats.rwNoByte++;
        if (stats.rwNoByte <= 5) {
            emit({
                spike: "byte-store-unresolved",
                insn: info.address + " " + info.mnemonic + " " + info.opStr,
                operands: info.operands.map(function (o) {
                    return o.type + ":" + o.size;
                }).join(",")
            });
        }
        return;
    }
    if (byte !== plan.head[0]) {
        stats.rwByteMismatch++;
        return;
    }
    const ea = computeEA(info.mem, context, info.next);
    if (plan.copySet[ea.toString()] === undefined) {
        plan.copySet[ea.toString()] = info.address;
        stats.candidates++;
        if (stats.candidates <= 8) {
            emit({
                spike: "candidate",
                n: stats.candidates,
                ea: ea.toString(),
                byte: byte,
                insn: info.address + " " + info.mnemonic + " " + info.opStr
            });
        }
    }
}

/* ======================================================================
 * Stage 2 -- find and bypass the hash_3 comparison
 * (port of wl-extract/staging/stage2.cpp)
 *
 *   sub 1  the first 2-byte read of dec_lic + 0x33 is the landmark, via the
 *          same guard-page mechanism as Stage 1
 *   sub 2  find 'cmp word ptr [reg1], reg2'; exactly one operand is the
 *          hash_3 we generated, the other is the value the program expects
 *   sub 3  hand dec_lic to Stage 3
 *
 * whatlicense forces the comparison with EFLAGS=0x200242 + PIN_ExecuteAt(addr+3).
 * Neither works in Frida (CpuContext has no flags field, and writing the pc has
 * no effect -- both verified in Spike 1), so the comparison is neutralised:
 * whichever operand holds our hash_3 is overwritten with the expected value, so
 * the cmp sets the flags on its own and the program's own branch does the rest.
 *
 * Sub-stage 2 needs instruction-level visibility, which a guard page cannot
 * give: the comparison reads a register, not dec_lic + 0x33 (whatlicense notes
 * WL shuffles the value through push/pop before using it). Stalker is
 * re-followed for that window and unfollowed again afterwards.
 * ====================================================================== */
const HASH3_OFFSET = 0x33;

const WORD_REGISTERS = {
    ax: "eax", cx: "ecx", dx: "edx", bx: "ebx",
    sp: "esp", bp: "ebp", si: "esi", di: "edi",
    r8w: "r8", r9w: "r9", r10w: "r10", r11w: "r11",
    r12w: "r12", r13w: "r13", r14w: "r14", r15w: "r15"
};

/* The 64-bit parent of a 16-bit register, for Frida's x64 CpuContext. It
 * exposes rax/rbx/.../rdx but NOT eax/edx, so mapping dx -> edx (the x86 name)
 * left context["edx"] undefined and every x64 comparison was rejected as
 * noReg. */
const WIDE_REGISTERS = {
    ax: "rax", cx: "rcx", dx: "rdx", bx: "rbx",
    sp: "rsp", bp: "rbp", si: "rsi", di: "rdi"
};

/* The CpuContext property to write a 16-bit operand's parent through.
 * Candidates in the same order stage2RegValue reads them, because which name a
 * CpuContext exposes depends on the architecture (x64 exposes rax, not eax). */
function stage2RegWriteName(context, regName) {
    const candidates = [];
    const parent = WORD_REGISTERS[regName];
    if (parent !== undefined) {
        candidates.push(parent);
    }
    const wide = WIDE_REGISTERS[regName];
    if (wide !== undefined) {
        candidates.push(wide);
    }
    candidates.push(regName);
    for (const name of candidates) {
        if (context[name] !== undefined && context[name] !== null) {
            return name;
        }
    }
    return null;
}

/* The register holding a 16-bit operand's value. Candidates are tried in turn
 * because which name a CpuContext exposes depends on the architecture. */
function stage2RegValue(context, regName) {
    const candidates = [];
    const parent = WORD_REGISTERS[regName];
    if (parent !== undefined) {
        candidates.push(parent);
    }
    const wide = WIDE_REGISTERS[regName];
    if (wide !== undefined) {
        candidates.push(wide);
    }
    candidates.push(regName);
    for (const name of candidates) {
        const value = context[name];
        if (value !== undefined && value !== null) {
            return { name: name, value: value };
        }
    }
    return null;
}

function stage2State() {
    if (plan.stage2 === undefined) {
        /* active starts true, not false. Stalker's transform runs once per
         * block at compile time, so a block compiled during Stage 0 would
         * never carry the Stage 2 callout if the gate were false then -- and
         * no amount of flushing helps, because the block only needs
         * recompiling if something in it changed. The compile-time gate is
         * therefore just "stage2 exists"; whether the callout does anything is
         * decided at run time by sub === 2. */
        plan.stage2 = {
            active: true, sub: 0, decLic: null, hash3: 0,
            guardStart: null, guardLength: 0, hits: 0, rearms: 0,
            /* Second guard range and the mp_int's digit buffer. mp_exptmod's
             * Y is an mp_int struct; whatlicense's dec_lic may be that struct
             * or the buffer inside it, so both +HASH3_OFFSET candidates stay
             * alive and whichever is read at decides the landmark. */
            guardStart2: null, guardLength2: 0, decLicBuf: null,
            rearmPending: false, cmpAddress: null, realHash3: null,
            cmpCandidates: 0, neutralised: 0, followed: [],
            insideAtFollow: 0
        };
    }
    return plan.stage2;
}

function stage2Log(event, detail) {
    emit({ spike: "stage2", event: event, detail: detail });
}

/* Arm one range page by page, tolerating pages that refuse.
 *
 * A single VirtualProtect over a 64KB span fails as a whole if any page in it is
 * not committed (round 32: guard=...0x10000 armed=false, so nothing was guarded
 * at all). Arming each page separately keeps the pages that do work and reports
 * how many. */
function stage2ArmOne(start, length) {
    const pageSize = Process.pageSize;
    const old = Memory.alloc(4);
    let armed = 0;
    const pages = Math.ceil(length / pageSize);
    stage2Log("arm-one", "start=" + start + " length=0x" + length.toString(16) +
        " pages=" + pages);
    for (let offset = 0; offset < length; offset += pageSize) {
        try {
            if (getVirtualProtect()(start.add(offset), pageSize,
                    PAGE_READWRITE | PAGE_GUARD, old) !== 0) {
                armed++;
            }
        } catch (e) {
            /* this page cannot be guarded; keep the rest */
        }
    }
    /* Report the return, not just the entry.  Round 25 logged stage2 start and
     * then nothing at all -- no armed, no following-now, none of the heartbeats
     * that follow it -- which means the deferred callback never got past
     * stage2ArmGuard.  The loop is a handful of pages, so "it is slow" does not
     * explain it; a fault storm does: arming a page the protection is actively
     * polling re-enters the exception handler (which disarms and re-arms) faster
     * than the JS thread can finish the loop. */
    stage2Log("arm-one-done", "start=" + start + " armed=" + armed + "/" + pages);
    return armed;
}

function stage2DisarmOne(start, length) {
    const pageSize = Process.pageSize;
    const old = Memory.alloc(4);
    for (let offset = 0; offset < length; offset += pageSize) {
        try {
            getVirtualProtect()(start.add(offset), pageSize, PAGE_READWRITE,
                old);
        } catch (e) {
            /* already gone */
        }
    }
}

function stage2ArmGuard() {
    const s2 = stage2State();
    let armed = 0;
    stage2Log("arm-begin", "guard1=" + s2.guardStart + "+0x" +
        s2.guardLength.toString(16) + " guard2=" + s2.guardStart2 + "+0x" +
        s2.guardLength2.toString(16) + " armBuffer=" + (s2.armBufferGuard === true));
    if (s2.guardStart !== null && s2.guardLength > 0) {
        armed += stage2ArmOne(s2.guardStart, s2.guardLength);
    }
    /* The buffer guard is opt-in, and off by default.
     *
     * Round 27 armed both ranges on six completions.  The dec_lic page
     * (guard1 = 0x14f000) armed 1/1 every single time; the licence buffer page
     * (guard2 = 0x6ae000) armed on three and on the other three the attempt
     * simply ended inside its first VirtualProtect -- and not one guard-fault
     * line was emitted, so the exception handler never ran: the fault that
     * arming that page provokes takes the process down before the message is
     * delivered.
     *
     * Nothing needs it any more.  hash_3 is read straight from the buffer
     * (bufHash3=0x6501, stable across addresses) and the comparison window opens
     * without the guard, so the only thing the buffer guard still does is kill
     * half the attempts that get this far. */
    if (s2.armBufferGuard === true && s2.guardStart2 !== null &&
        s2.guardLength2 > 0) {
        armed += stage2ArmOne(s2.guardStart2, s2.guardLength2);
    }
    stage2Log("arm-end", "armed=" + armed);
    return armed > 0;
}

function stage2DisarmGuard() {
    const s2 = stage2State();
    if (s2.guardStart !== null && s2.guardLength > 0) {
        stage2DisarmOne(s2.guardStart, s2.guardLength);
    }
    if (s2.guardStart2 !== null && s2.guardLength2 > 0) {
        stage2DisarmOne(s2.guardStart2, s2.guardLength2);
    }
}

/* Is this address inside either guarded page? */
function stage2InGuardRange(s2, address) {
    const ranges = [[s2.guardStart, s2.guardLength],
                    [s2.guardStart2, s2.guardLength2]];
    for (const range of ranges) {
        if (range[0] === null || range[0] === undefined || range[1] <= 0) {
            continue;
        }
        if (address.compare(range[0]) >= 0 &&
            address.compare(range[0].add(range[1])) < 0) {
            return true;
        }
    }
    return false;
}

/* hash_3 sits HASH3_OFFSET bytes into the decrypted license. Two candidates are
 * kept alive: the mp_int mp_exptmod was handed (its 4th argument, which is what
 * the port has) and the digit buffer that struct points at -- which of the two
 * whatlicense's x86 dec_lic refers to is not settled, and reading the wrong one
 * gives a hash_3 of stack/heap garbage that can never match. */
/* The page-aligned start and length of the allocation containing `pointer`,
 * capped so a large mapping does not become thousands of VirtualProtect calls.
 * Falls back to the single containing page when the range is unknown. */
function stage2GuardRange(pointer) {
    const pageSize = Process.pageSize;
    const page = pointer.and(ptr(pageSize - 1).not());
    /* Span is configurable: the default covers the containing allocation, and a
     * diagnostic run can widen it to find out which addresses the protection
     * actually touches (rounds 31/33: neither dec_lic nor the pre-call dp is
     * touched at all, so the real output buffer is elsewhere in this heap). */
    const cap = plan.guardSpan || 0x10000;
    let length = pageSize;
    const range = Process.findRangeByAddress(pointer);
    if (range !== null) {
        const span = range.base.add(range.size).sub(page);
        length = span.compare(cap) > 0 ? cap : span.toInt32();
    } else if (cap > pageSize) {
        length = cap;
    }
    return { start: page, length: length };
}

function stage2IsHash3Address(s2, address) {
    if (address.compare(s2.decLic.add(HASH3_OFFSET)) === 0) {
        return true;
    }
    return s2.decLicBuf !== null &&
        address.compare(s2.decLicBuf.add(HASH3_OFFSET)) === 0;
}

/* Re-resolve the digit buffer after the RSA call has actually run.
 *
 * startStage2 is called from the mp_exptmod hook's onEnter, i.e. *before* the
 * call, and at that moment the output mp_int Y is uninitialised -- its digit
 * pointer refers to a small or empty allocation. Round 20 showed exactly that:
 * dec_lic=0x14f890 resolved to buf=0x718600, and bufHash3 came back
 * "unreadable", so neither guarded page was the plaintext buffer and the guard
 * was never hit (stage2Sub stayed 1 on both real completions).
 *
 * A tick later mp_exptmod has written Y, so dp points at the decrypted license
 * and dp + HASH3_OFFSET is the value Stage 2 is looking for. */
function stage2RefreshBuffer() {
    const s2 = stage2State();
    /* Entry line, capped rather than suppressed. The earlier "quiet after two
     * refreshes" rule hid every refresh in the real runs (round 29: three
     * completions, one rearm line, and that one was the mimic's), which made
     * "the refresh never ran" and "the refresh ran and did nothing"
     * indistinguishable -- the same trap as the other logging gaps. */
    s2.refreshes = (s2.refreshes || 0) + 1;
    const quiet = s2.refreshes > 6;
    if (!quiet) {
        stage2Log("refresh-entry", "#" + s2.refreshes +
            " active=" + s2.active + " sub=" + s2.sub +
            " decLic=" + s2.decLic);
    }
    if (!s2.active || s2.sub !== 1 || s2.decLic === null) {
        return;
    }
    let candidate = null;
    try {
        candidate = s2.decLic.add(IS_IA32 ? 0x0c : 0x10).readPointer();
    } catch (e) {
        candidate = null;
    }
    if (candidate === null || candidate.isNull()) {
        if (!quiet) {
            stage2Log("rearm", "no digit pointer at " + s2.decLic);
        }
        return;
    }
    if (Process.findRangeByAddress(candidate) === null) {
        if (!quiet) {
            stage2Log("rearm", "buf " + candidate + " not mapped");
        }
        return;
    }
    const range = stage2GuardRange(candidate.add(HASH3_OFFSET));
    const page = range.start;
    s2.decLicBuf = candidate;
    let hash3 = "unreadable";
    try {
        hash3 = "0x" + candidate.add(HASH3_OFFSET).readU16().toString(16);
    } catch (e) {
        /* leave the marker */
    }
    /* Dump the head of the decrypted buffer, once.
     *
     * Rounds 24/26/27 armed Stage 2 on 2, 3 and 1 real completions and got 5, 0
     * and 0 guard hits: the protection sometimes never touches either guarded
     * page, i.e. it gives up *before* the hash_3 comparison. Whether it does is
     * a property of the plaintext the swap produced, not of our timing -- so
     * the plaintext is the thing to look at. This is the input for making the
     * content deterministic (whatlicense's stage 4-5) instead of re-rolling the
     * lottery. */
    if (s2.bufHeadLogged !== true) {
        s2.bufHeadLogged = true;
        let head = "unreadable";
        try {
            head = hex(new Uint8Array(candidate.readByteArray(0x40)));
        } catch (e) {
            /* leave the marker */
        }
        stage2Log("buf-head", "buf=" + candidate + " licSize=" +
            plan.licSize + " head=" + head);
    }
    if (page.compare(s2.guardStart) === 0 ||
        (s2.guardStart2 !== null && page.compare(s2.guardStart2) === 0)) {
        if (!quiet) {
            stage2Log("rearm", "buf=" + candidate + " hash3=" + hash3 +
                " page already guarded (" + page + ")");
        }
        return;
    }
    s2.guardStart2 = page;
    s2.guardLength2 = range.length;
    let armed = false;
    let error = null;
    try {
        armed = stage2ArmGuard();
    } catch (e) {
        error = String(e);
    }
    if (!quiet) {
        stage2Log("rearm", "buf=" + candidate + " hash3=" + hash3 +
            " guard2=" + page + " armed=" + armed +
            (error === null ? "" : " arm-error=" + error));
    }
}

/* Offset of `address` inside the decrypted buffer, or -1 if it is outside.
 *
 * The landmark used to require an exact match on whatlicense's fixed +0x33.
 * Round 23 showed that is wrong for this sample: the guard was armed on the
 * buffer page and did catch the protection's accesses, but it read the *start*
 * of the buffer (buf=0x505010, reads at 0x505010 and 0x5050a0) while the
 * landmark test demanded 0x505043. 0x33 is a constant whatlicense measured on
 * its own samples, not a property of the format.
 *
 * Accept any access inside the buffer and report where it landed, so the real
 * offset comes from data. */
function stage2Hash3Offset(s2, address) {
    if (s2.decLicBuf === null) {
        return -1;
    }
    const delta = address.sub(s2.decLicBuf);
    if (delta.compare(0) < 0) {
        return -1;
    }
    const span = Math.max(plan.licSize || 0x200, 0x200);
    if (delta.compare(span) >= 0) {
        return -1;
    }
    return delta.toInt32();
}

/* Same rule as Stage 1: re-arm only from the JS thread, never inside the
 * exception handler, or the retrying instruction faults on itself forever. */
function stage2ScheduleRearm() {
    const s2 = stage2State();
    if (!s2.active || s2.sub !== 1 || s2.rearmPending ||
        s2.rearms >= MAX_REARMS) {
        return;
    }
    s2.rearmPending = true;
    setTimeout(function () {
        s2.rearmPending = false;
        if (plan.stage2.active && plan.stage2.sub === 1) {
            plan.stage2.rearms++;
            stage2ArmGuard();
        }
    }, 2);
}

/* Find the decrypted buffer by its contents instead of by argument.
 *
 * Rounds 31/33 armed the allocation holding dec_lic (the 4th argument) and the
 * one holding the pre-call dp; the protection touched neither, so neither is the
 * object it reads afterwards, and the real buffer's location is unknown. With
 * the identity key in play the RSA output is the input value itself, i.e. the
 * licence file bytes, so the buffer can simply be found by searching memory for
 * those bytes. Anything that matches and is not lic_copy itself is a candidate.
 */
function stage2LocateBufferByContent() {
    const s2 = stage2State();
    const copy = plan.licCopy === undefined || plan.licCopy === null
        ? null : ptr(plan.licCopy);
    if (copy === null) {
        stage2Log("buf-scan", "no lic_copy to search for");
        return;
    }
    let pattern = null;
    try {
        /* Memory.scanSync takes a pattern string or a MatchPattern, not the
         * ArrayBuffer that readByteArray returns. Passing the ArrayBuffer threw
         * "expected either a pattern string or a MatchPattern object" on every
         * call -- round 64 finally showed the message -- which is why the sweep
         * always reported scanned=0x0 and why every round armed Stage 2 on a
         * garbage address. scanForHead builds a hex string and has always worked;
         * do the same here. */
        const raw = new Uint8Array(copy.readByteArray(8));
        pattern = Array.prototype.map.call(raw, function (byte) {
            return byte.toString(16).padStart(2, "0");
        }).join(" ");
    } catch (e) {
        stage2Log("buf-scan", "lic_copy unreadable: " + e);
        return;
    }
    const hits = [];
    let scanned = 0;
    let ranges = [];
    try {
        /* Writable ranges only.
         *
         * The decrypted licence lives in a read-write buffer; the encrypted
         * lic_copy and the licence file the protection mapped are read-only. With
         * the identity key both hold the same bytes, so searching read-only
         * ranges finds the mapped file every time and never the buffer we want:
         * round 28 re-pointed decLicBuf at 0x53e7c0 (read-only) while stage2
         * start had resolved the real buffer as 0x6ae800, hash_3 read 0 at the
         * new address, and all 2413 comparison sites were refused. */
        ranges = Process.enumerateRanges("rw-");
    } catch (e) {
        stage2Log("buf-scan", "enumerateRanges failed: " + e);
        return;
    }
    for (let i = 0; i < ranges.length && hits.length < 6; i++) {
        const range = ranges[i];
        if (range.size > 0x4000000) {
            continue;
        }
        try {
            const found = Memory.scanSync(range.base, range.size, pattern);
            scanned += range.size;
            for (let j = 0; j < found.length && hits.length < 6; j++) {
                const at = found[j].address;
                /* lic_copy itself is not the decrypted buffer. */
                if (at.compare(copy) >= 0 && at.compare(copy.add(0x2000)) < 0) {
                    continue;
                }
                hits.push(at);
            }
        } catch (e) {
            /* unreadable range */
        }
    }
    stage2Log("buf-scan", "hits=" + hits.length + " scanned=0x" +
        scanned.toString(16) + " at=" +
        hits.map(function (a) { return a.toString(); }).join(","));
    if (hits.length === 0 && s2.decLic !== null && s2.decLic !== undefined) {
        /* The global sweep is unreliable here: round 61 reported scanned=0x0,
         * i.e. every candidate range either exceeded the size cap or failed to
         * scan, and Stage 2 armed its monitor on a garbage address (bufHash3
         * unreadable) that could never be hit.
         *
         * dec_lic is the RSA output, and under the identity key that output is
         * the licence bytes themselves, so the range holding dec_lic is where the
         * decrypted buffer must be. Scan just that one -- one range, no cap, no
         * dependence on how the process happens to lay out its heaps. */
        try {
            const owner = Process.findRangeByAddress(s2.decLic);
            if (owner !== null) {
                stage2Log("buf-scan-anchor", "scanning the dec_lic range " +
                    owner.base + "+0x" + owner.size.toString(16) + " (" +
                    owner.protection + ")");
                const found = Memory.scanSync(owner.base, owner.size, pattern);
                for (let j = 0; j < found.length && hits.length < 6; j++) {
                    const at = found[j].address;
                    if (at.compare(copy) >= 0 &&
                        at.compare(copy.add(0x2000)) < 0) {
                        continue;
                    }
                    hits.push(at);
                }
                stage2Log("buf-scan-anchor", "hits=" + hits.length);
            }
        } catch (e) {
            stage2Log("buf-scan-anchor", "failed: " + String(e));
        }
    }
    if (hits.length === 0) {
        return;
    }
    /* Belt and braces: never re-point decLicBuf at a read-only range. */
    const owner = Process.findRangeByAddress(hits[0]);
    if (owner === null || owner.protection.indexOf("w") < 0) {
        stage2Log("buf-scan", "hit " + hits[0] + " is not writable (" +
            (owner === null ? "no range" : owner.protection) + "); keeping " +
            s2.decLicBuf);
        return;
    }
    const range = stage2GuardRange(hits[0].add(HASH3_OFFSET));
    stage2Log("buf-scan-adopt", "buf " + s2.decLicBuf + " -> " + hits[0] +
        " protection=" + owner.protection);
    s2.decLicBuf = hits[0];
    if (range.start.compare(s2.guardStart) === 0 ||
        (s2.guardStart2 !== null && range.start.compare(s2.guardStart2) === 0)) {
        stage2Log("buf-scan", "already guarded " + range.start);
        return;
    }
    s2.guardStart2 = range.start;
    s2.guardLength2 = range.length;
    setTimeout(function () {
        let armed = false;
        try {
            armed = stage2ArmGuard();
        } catch (e) {
            armed = false;
        }
        stage2Log("buf-scan-armed", "page=" + range.start + " len=0x" +
            range.length.toString(16) + " armed=" + armed);
    }, 0);
}

function startStage2(decLic) {
    const s2 = stage2State();
    s2.active = true;
    s2.sub = 1;
    s2.decLic = ptr(decLic);
    /* The 4th argument of mp_exptmod is an mp_int (libtommath: used, alloc,
     * sign, then the digit pointer). Resolve that pointer as a second hash_3
     * candidate -- see stage2IsHash3Address. */
    s2.decLicBuf = null;
    try {
        const candidate = s2.decLic.add(IS_IA32 ? 0x0c : 0x10).readPointer();
        const range = candidate.isNull()
            ? null : Process.findRangeByAddress(candidate);
        if (range !== null) {
            s2.decLicBuf = candidate;
        }
    } catch (e) {
        s2.decLicBuf = null;
    }
    /* Nothing resolved from the struct: go and find the buffer.
     *
     * Round 62 completed Stage 1 end to end (landmark, sub2, sub3, sub4, swap) and
     * then reported buf=null with no buf-scan line at all -- the locator was never
     * called on this path, so neither the sweep nor the dec_lic-range fallback got
     * a chance to run, and Stage 2 armed nothing. */
    if (s2.decLicBuf === null) {
        try {
            stage2LocateBufferByContent();
        } catch (e) {
            stage2Log("buf-locate-failed", String(e));
        }
    }
    /* Take hash_3 from the *buffer*, not from the struct.
     *
     * dec_lic is the mp_int struct (used/alloc/sign at 0,4,8 and dp at 0x10), so
     * dec_lic + 0x33 is 0x33 bytes past a 0x18-byte structure -- whatever it
     * reads is unrelated to the licence. Rounds 35 and 37 both reported
     * hash3=0x4000 from there, while the buffer identified from the struct's own
     * dp field gave bufHash3=0x6501 in both runs, at different buffer addresses.
     * A value that is stable across runs and allocations is a licence constant;
     * a value read past the end of a struct is not. The cmp matcher keys on this
     * value, so it was matching nothing. */
    try {
        s2.hash3 = s2.decLicBuf !== null
            ? s2.decLicBuf.add(HASH3_OFFSET).readU16()
            : s2.decLic.add(HASH3_OFFSET).readU16();
    } catch (e) {
        s2.hash3 = 0;
    }
    const pageSize = Process.pageSize;
    /* Guard the allocations the two candidates live in, page by page.
     *
     * Round 31 armed one page at dec_lic + 0x33 and one at the pre-call dp, and
     * the protection touched neither -- not even a write, although the RSA call
     * must write its output somewhere. So dec_lic (the 4th argument) is not the
     * output buffer we assumed, and the real one is allocated inside mp_exptmod.
     * Covering the whole containing allocation turns "the protection reads
     * elsewhere in this heap" into a guard-hit with an address. */
    const primary = stage2GuardRange(s2.decLic.add(HASH3_OFFSET));
    s2.guardStart = primary.start;
    s2.guardLength = primary.length;
    s2.guardStart2 = null;
    s2.guardLength2 = 0;
    if (s2.decLicBuf !== null) {
        const second = stage2GuardRange(s2.decLicBuf.add(HASH3_OFFSET));
        if (second.start.compare(s2.guardStart) !== 0) {
            s2.guardStart2 = second.start;
            s2.guardLength2 = second.length;
        }
    }
    let bufHash3 = null;
    if (s2.decLicBuf !== null) {
        try {
            bufHash3 = "0x" + s2.decLicBuf.add(HASH3_OFFSET).readU16().toString(16);
        } catch (e) {
            bufHash3 = "unreadable";
        }
    }
    /* Log first, arm after.
     *
     * The arm used to run inside the mp_exptmod hook, and a wide guard_span
     * makes that hundreds of VirtualProtect calls inside a hook -- round 34's
     * 1MB span never returned and the real sample produced no stage2 start line
     * at all. Logging first means the range is visible even if arming is slow,
     * and deferring the arm keeps the target's hook short. */
    stage2Log("start", "dec_lic=" + s2.decLic + " hash3=0x" +
        s2.hash3.toString(16) + " guard=" + s2.guardStart + "+0x" +
        s2.guardLength.toString(16) + " buf=" + s2.decLicBuf +
        " bufHash3=" + bufHash3 + " guard2=" + s2.guardStart2);
    setTimeout(function () {
        let armed = false;
        let error = null;
        try {
            armed = stage2ArmGuard();
        } catch (e) {
            error = String(e);
        }
        stage2Log("armed", "armed=" + armed +
            (error === null ? "" : " arm-error=" + error));
        /* Open the comparison window now, without waiting for the guard.
         *
         * stage2FollowThreads -- the only entry to the Stalker window that does
         * the cmp matching -- is reached solely from the guard's hash3-read
         * branch (which sets sub = 2). So when the guard does not fire, the
         * window never opens and the matcher never runs: rounds 37/38/39
         * reported cmp-mem-shape (the scan) with cmp-site (the executed apply)
         * at zero, which reads like "the protection never compares" but is
         * really "we never looked".
         *
         * The guard existed only to learn hash_3 from the read the protection
         * performs. That value is now taken straight from the buffer and is
         * stable across runs (0x6501 at three different buffer addresses), so
         * the guard is no longer needed to arm the matcher. The guard stays
         * armed -- it costs nothing and still reports where the protection
         * reads -- but it no longer gates the window. */
        if (s2.sub === 1) {
            s2.sub = 2;
            stage2Log("following-now", "window opened without the guard");
            /* Stop tracing, and watch the one address that matters.
             *
             * whatlicense's stage2.cpp does this in two steps, and both are worth
             * copying exactly:
             *
             *   1. hash3 = rword(dec_lic + 0x33)          -- our license's value
             *   2. wait for a read of dec_lic + 0x33 of size 2
             *   3. from there, find `cmp word ptr [reg1], reg2` where one operand
             *      equals hash3; the other one is the protection's real hash_3
             *
             * Step 2 is the trigger we kept trying to reproduce with a guard page
             * (which killed the process) and with an always-on Stalker window
             * (which ran at ~93k instructions/s, a hundredfold slowdown, and is
             * why the protection never reached its OEP). MemoryAccessMonitor is
             * native, re-arms itself, and costs nothing per instruction.
             *
             * And the transform that Stage 1 needs is attached to every thread at
             * map time and never detached, so the slowdown was permanent. Unfollow
             * here: Stage 1 is done with it, Stage 2 only needs a short window
             * once the read shows up, and the OEP needs full speed. */
            stage2UnfollowAll();
            stage2ArmHash3Monitor();
            return;
        }
    }, 0);
}

/* Native access watch on the license buffer.
 *
 * whatlicense's find_hash_read is `(ea == dec_lic + 0x33) && (size == 2)`, but
 * 0x33 is an offset in the version whatlicense was written against. Round 54
 * watched exactly that address and the protection never read it once -- while a
 * page-shared read did arrive, so the watch was live. Watch the whole buffer
 * instead and report which offsets are actually read and what 2-byte values live
 * there: that measures the real hash_3 offset in this WinLicense build rather than
 * assuming whatlicense's. */
function stage2ArmHash3Monitor() {
    const s2 = stage2State();
    if (s2.decLicBuf === null || s2.decLicBuf === undefined) {
        stage2Log("monitor", "no decLicBuf; cannot arm");
        return;
    }
    const address = s2.decLicBuf.add(HASH3_OFFSET);
    s2.hash3Address = address;
    s2.hash3Reads = 0;
    s2.fieldsSeen = {};
    try {
        MemoryAccessMonitor.enable({
            base: s2.decLicBuf,
            size: Math.max(2, plan.licSize)
        }, {
            onAccess: function (details) {
                s2.hash3Reads = (s2.hash3Reads || 0) + 1;
                /* Record every distinct offset inside the buffer that gets read,
                 * with its value, so the field the protection actually inspects
                 * can be read off the log. */
                const offset = details.address.sub(s2.decLicBuf).toInt32();
                if (offset >= 0 && offset < Math.max(2, plan.licSize)) {
                    const key = offset.toString(16);
                    if (s2.fieldsSeen[key] === undefined) {
                        let value = "?";
                        try {
                            value = "0x" +
                                details.address.readU16().toString(16);
                        } catch (e) {
                            /* unreadable */
                        }
                        s2.fieldsSeen[key] = value;
                        if (Object.keys(s2.fieldsSeen).length <= 40) {
                            stage2Log("field-read", "offset=0x" + key +
                                " value=" + value +
                                " op=" + details.operation +
                                " from=" + details.from);
                        }
                    }
                }
                const exact = details.address.compare(s2.hash3Address) >= 0 &&
                    details.address.compare(s2.hash3Address.add(2)) < 0;
                if (!exact) {
                    s2.hash3Collateral = (s2.hash3Collateral || 0) + 1;
                    if (s2.hash3Collateral <= 4) {
                        stage2Log("monitor-collateral",
                            "read@" + details.address + " from " +
                            details.from + " (not the hash_3 field)");
                    }
                    return;
                }
                stage2Log("monitor-hit", "#" + s2.hash3Reads + " " +
                    details.operation + "@" + details.address + " from " +
                    details.from + " pc=" + details.context[PC_REG] +
                    " ours=0x" + s2.hash3.toString(16));
                if (s2.hash3Hits !== true) {
                    /* The protection is about to compare. Open the window for the
                     * comparison only -- whatlicense notes WL pushes and pops the
                     * value a few times first, so it is not the read instruction
                     * itself that does the comparing. */
                    s2.hash3Hits = true;
                    s2.sub = 2;
                    setTimeout(stage2FollowThreads, 0);
                }
            }
        });
        stage2Log("monitor-armed", "addr=" + address + " size=2");
    } catch (e) {
        stage2Log("monitor", "enable failed: " + String(e));
    }
}

/* Detach the map-time transform from every thread.
 *
 * Stage 1's landmark comes from that transform; Stage 2 does not need it until
 * the hash_3 read happens, and the protection cannot reach its OEP while every
 * instruction costs a JS callback. */
function stage2UnfollowAll() {
    let count = 0;
    for (const thread of Process.enumerateThreads()) {
        try {
            Stalker.unfollow(thread.id);
            count++;
        } catch (e) {
            /* best effort */
        }
    }
    try {
        Stalker.flush();
    } catch (e) {
        /* best effort */
    }
    stage2Log("unfollow-all", "threads=" + count + " (Stage 1 done with the transform)");
}

/* Read breakpoint on the licence's hash_3 field.
 *
 * The Stalker window that used to find the comparison site costs a JS callback
 * per instruction -- rounds 30-32 processed ~4.2M instructions in ~45s, about
 * 93k/s, a hundredfold slowdown -- which is why the protection never reaches its
 * OEP, and it saturates the JS thread badly enough that whether the matcher or
 * the timers get a slot is luck.
 *
 * A data breakpoint is native: the CPU traps when the protection reads hash_3 and
 * the handler sees the PC, which is the comparison site. One trap, no
 * per-instruction cost, and the target keeps running at full speed. */
function stage2ArmHash3HwBreak() {
    const s2 = stage2State();
    if (s2.decLicBuf === null || s2.decLicBuf === undefined) {
        stage2Log("hw3", "no decLicBuf; cannot arm");
        return;
    }
    const address = s2.decLicBuf.add(HASH3_OFFSET);
    let value = "unreadable";
    try {
        value = "0x" + address.readU16().toString(16);
    } catch (e) {
        /* leave the marker */
    }
    s2.hw3Address = address;
    s2.hw3Hits = 0;
    s2.hw3Threads = [];
    let applied = 0;
    let failed = 0;
    for (const thread of Process.enumerateThreads()) {
        let ok = false;
        try {
            ok = hwBreakApplyToThread(thread.id, [address, null, null], true);
        } catch (e) {
            ok = false;
        }
        if (ok) {
            applied++;
            s2.hw3Threads.push(thread.id);
        } else {
            failed++;
        }
    }
    stage2Log("hw3-armed", "addr=" + address + " value=" + value +
        " applied=" + applied + " failed=" + failed);
}

function stage2OnGuardAccess(details) {
    const s2 = plan.stage2;
    if (s2 === undefined || !s2.active || s2.guardStart === null) {
        return false;
    }
    /* Count every entry, before any early return, and report the first few and
     * then sparsely.  If arming a page the protection polls produces a fault
     * storm, this counter is what shows it: the handler disarms and re-arms per
     * fault, so a storm keeps the JS thread inside the handler and stage2ArmGuard
     * never returns (round 25: stage2 start, then no armed, no following-now, no
     * heartbeats). */
    s2.faults = (s2.faults || 0) + 1;
    if (s2.faults <= 5 || s2.faults % 200 === 0) {
        stage2Log("guard-fault", "#" + s2.faults + " " +
            (details.memory ? details.memory.operation : "?") + "@" +
            (details.memory ? details.memory.address : "?"));
    }
    const memory = details.memory || null;
    let address = null;
    let operation = "read";
    if (memory !== null) {
        address = memory.address;
        operation = memory.operation || "read";
    }
    if ((address === null || address === undefined) &&
        details.address !== undefined && details.address !== null) {
        address = details.address;
    }
    if (address === null || address === undefined) {
        return false;
    }
    if (!stage2InGuardRange(s2, address)) {
        return false;
    }
    s2.hits++;
    if (s2.hits <= 12) {
        const hctx = details.context || null;
        let offsetText = "off=?";
        if (s2.decLicBuf !== null) {
            /* Signed distance from the decrypted buffer, so a hit can be read
             * directly as "inside the buffer at +N" or "past the end by N".
             * hash3At used to print the constant dec_lic + 0x33, which said
             * nothing about where the protection actually read. */
            try {
                offsetText = "off=" + (address.sub(s2.decLicBuf).toInt32() >= 0
                    ? "+" : "-") + "0x" + Math.abs(
                    address.sub(s2.decLicBuf).toInt32()).toString(16);
            } catch (e) {
                offsetText = "off=?";
            }
        }
        stage2Log("guard-hit", "#" + s2.hits + " op=" + operation +
            " addr=" + address + " pc=" + (hctx === null ? "?" :
                hctx[PC_REG]) + " " + offsetText +
            " buf=" + s2.decLicBuf +
            " bufHash3At=" + (s2.decLicBuf === null ? "none" :
                s2.decLicBuf.add(HASH3_OFFSET)));
    }
    if (s2.sub !== 1) {
        stage2DisarmGuard();
        return true;
    }
    /* Two-stage arming, so nothing depends on the RSA call returning.
     *
     * The protection reads the output mp_int's dp field immediately after the
     * call, and only then touches the buffer. Round 30 showed why arming from
     * the hook's onLeave cannot work: refresh-entry appeared exactly once per
     * run, with sub=0 and decLic=null (i.e. before Stage 1 completed), and never
     * again -- the RSA call's own onLeave does not fire. So startStage2's guard
     * stayed on the *pre-call* buffer page for the whole run and the real buffer
     * was never guarded.
     *
     * The dp read is inside the struct page that is already guarded, and it
     * yields the buffer address directly. Arm the second page from here and let
     * the buffer read be the landmark. */
    if (operation === "read" &&
        address.compare(s2.decLic.add(mpIntDpOffset())) === 0) {
        let buf = null;
        try {
            buf = address.readPointer();
        } catch (e) {
            buf = null;
        }
        if (buf !== null && !buf.isNull() &&
            Process.findRangeByAddress(buf) !== null) {
            s2.decLicBuf = buf;
            const dpRange = stage2GuardRange(buf.add(HASH3_OFFSET));
            const dpPage = dpRange.start;
            const already = dpPage.compare(s2.guardStart) === 0 ||
                (s2.guardStart2 !== null &&
                 dpPage.compare(s2.guardStart2) === 0);
            stage2Log("dp-read", "buf=" + buf + " page=" + dpPage +
                " len=0x" + dpRange.length.toString(16) +
                " alreadyGuarded=" + already);
            if (!already) {
                s2.guardStart2 = dpPage;
                s2.guardLength2 = dpRange.length;
                /* Arming from the exception handler would fault on the retrying
                 * instruction; defer to the JS thread. */
                setTimeout(stage2ArmGuard, 0);
            }
        }
        stage2ScheduleRearm();
        return true;
    }
    const offset = stage2Hash3Offset(s2, address);
    const exact = stage2IsHash3Address(s2, address);
    if (operation !== "read" || offset < 0) {
        /* Not inside the decrypted buffer. Log one miss with the buffer's
         * extent: that is what says whether the guarded object is even the
         * right one. */
        if (s2.missLogged !== true) {
            s2.missLogged = true;
            stage2Log("hash3-miss", "op=" + operation + " addr=" + address +
                " buf=" + s2.decLicBuf + " bufEnd=" +
                (s2.decLicBuf === null ? "none" :
                    s2.decLicBuf.add(Math.max(plan.licSize || 0x200, 0x200))));
        }
        stage2ScheduleRearm();
        return true;
    }
    let value = "unreadable";
    try {
        value = "0x" + address.readU16().toString(16);
    } catch (e) {
        /* leave the marker */
    }
    const ctx = details.context || null;
    stage2Log("hash3-read", "pc=" + (ctx === null ? "?" : ctx[PC_REG]) +
        " offset=0x" + offset.toString(16) + " value=" + value +
        " exact=" + exact + " hits=" + s2.hits);
    /* hash_3 is a field of the licence -- buffer + 0x33 -- not whatever word the
     * protection happens to load inside the buffer.
     *
     * Taking the read value unconditionally let a zero word inside the licence
     * clobber the reference: round 23 logged hash3=0x6501 at stage2 start, then
     * every cmp-site showed ours=0x0, and the zero-guard (correctly) refused
     * every match. Adopt the read only when it is non-zero and we have nothing
     * better; otherwise keep the value taken from the field. */
    let read = null;
    try {
        read = address.readU16();
    } catch (e) {
        /* keep whatever startStage2 captured */
    }
    if (read !== null && read !== 0 && !s2.hash3) {
        s2.hash3 = read;
    }
    s2.sub = 2;
    stage2DisarmGuard();
    /* Deferred, like everything else that is not "read a register": unfollow +
     * flush + follow across every thread is far too much work to run inside
     * the exception handler. Doing it inline left the window tracing ~138
     * instructions, the same class of mistake as calling Thread.backtrace
     * from the handler in Stage 1. */
    setTimeout(stage2FollowThreads, 0);
    return true;
}

function stage2FollowThreads() {
    const s2 = stage2State();
    /* Flush, and do not touch thread follow state here.
     *
     * Both directions hang the target when called from this deferred callback:
     * unfollow (b22655b) and follow (ca57e0d) each left stdout stopped right
     * after SPIKE2_RSA block=33 with no SPIKE2_HASH3 line and no window event,
     * and grew the run from 26.6s to 37.6s. This callback runs on the thread
     * that just took the guard violation, so Stalker's thread bookkeeping
     * cannot be touched from it at all. Re-attaching has to happen from the
     * JS thread, before the read -- see handoff 7.25/7.26. */
    let flushed = false;
    try {
        Stalker.flush();
        flushed = true;
    } catch (e) {
        /* best effort */
    }
    s2.insideAtFollow = stats.inside;
    s2.instructionsAtFollow = stats.instructions;
    s2.outsideAtFollow = stats.outside;
    stage2Log("following", "flushed=" + flushed + " threads=" +
        Process.enumerateThreads().length + " instructions=" +
        stats.instructions + " inside=" + stats.inside +
        " outside=" + stats.outside);
    /* Bounded window: if the comparison never shows up, say so rather than
     * leaving the target slowed down for the rest of the run. */
    setTimeout(function () {
        if (plan.stage2.sub === 2) {
            /* Report all three counters. stats.instructions counts every
             * instruction the transform visits, before the module filter, so
             * its delta separates "the transform is not running" from "it runs
             * but everything it sees is outside the main module" -- with only
             * stats.inside reported those two look identical. */
            stage2Log("cmp-not-found", "no hash_3 comparison in the window; " +
                "cmp seen=" + (s2.scanCmp || 0) +
                " no-mem-or-reg=" + (s2.scanNoMemReg || 0) +
                " mem-not-word=" + (s2.scanMemNotWord || 0) +
                " reg-not-word=" + (s2.scanRegNotWord || 0) +
                " lastReg=" + (s2.scanLastReg || "-") +
                " | callouts=" + (s2.applyRuns || 0) +
                " noBase=" + (s2.applyNoBase || 0) +
                " badRead=" + (s2.applyBadRead || 0) +
                " noReg=" + (s2.applyNoReg || 0) +
                " visited=" + (stats.instructions - s2.instructionsAtFollow) +
                " inside=" + (stats.inside - s2.insideAtFollow) +
                " outside=" + (stats.outside - s2.outsideAtFollow));
        }
    }, 8000);
}

function stage2Unfollow() {
    const s2 = stage2State();
    for (const tid of s2.followed) {
        try {
            Stalker.unfollow(tid);
        } catch (e) {
            /* best effort */
        }
    }
    try {
        Stalker.flush();
    } catch (e) {
        /* best effort */
    }
    s2.followed = [];
}

/* Called from the Stalker transform. Returns a site description when the
 * instruction is 'cmp word ptr [reg1], reg2' -- whatlicense's
 * isWordPtrRegCmp -- or null. The Instruction object is only valid inside the
 * transform, so the values are read later from the callout's context. */
function stage2RecogniseCmp(insn) {
    const s2 = plan.stage2;
    if (insn.mnemonic !== "cmp") {
        return null;
    }
    if (s2 !== undefined) {
        s2.scanCmp = (s2.scanCmp || 0) + 1;
    }
    if (insn.operands.length !== 2) {
        return null;
    }
    let mem = null;
    let reg = null;
    for (const operand of insn.operands) {
        if (operand.type === "mem") {
            mem = operand;
        } else if (operand.type === "reg") {
            reg = operand;
        }
    }
    if (mem === null || reg === null) {
        if (s2 !== undefined) {
            s2.scanNoMemReg = (s2.scanNoMemReg || 0) + 1;
        }
        return null;
    }
    /* Only the memory operand's width is checked. Frida reports a 16-bit
     * register operand inconsistently -- sometimes as the full 32-bit width
     * -- so requiring reg.size === 2 rejected genuine matches, and the window
     * then reported "cmp-not-found" with nothing to explain it. The register
     * name is the reliable signal. */
    if (mem.size !== 2) {
        if (s2 !== undefined) {
            s2.scanMemNotWord = (s2.scanMemNotWord || 0) + 1;
        }
        return null;
    }
    if (s2 !== undefined && s2.scanShapeLogged !== true) {
        s2.scanShapeLogged = true;
        try {
            const v = mem.value;
            let shape = typeof v;
            if (v !== null && typeof v === "object") {
                shape += " keys=[" + Object.keys(v).join(",") + "]" +
                    " base=" + String(v.base) +
                    " index=" + String(v.index) +
                    " disp=" + String(v.disp);
            } else {
                shape += " str=" + String(v);
            }
            stage2Log("cmp-mem-shape", "type=" + shape +
                " resolved=" + stage2MemBaseOf(mem) + " size=" + mem.size);
        } catch (e) {
            /* diagnostics must never break recognition */
        }
    }
    const regName = String(reg.value).trim();
    if (WORD_REGISTERS[regName] === undefined) {
        if (s2 !== undefined) {
            s2.scanRegNotWord = (s2.scanRegNotWord || 0) + 1;
            s2.scanLastReg = regName;
        }
        return null;
    }
    return {
        address: insn.address.toString(),
        memBase: stage2MemBaseOf(mem),
        regName: regName
    };
}

/* The base register of a Frida x86 memory operand. `operand.value` is NOT the
 * base register name here -- it is an object, and String() of it is the literal
 * "[object Object]", which then fails the CpuContext lookup in stage2ApplyCmp.
 * That one detail is what kept Stage 2 reporting "cmp-not-found" with exactly
 * one callout fired and noBase=1. Accept a string when Frida gives one,
 * otherwise pull `base` (a string, or a nested object carrying `value`) out. */
function stage2MemBaseOf(mem) {
    const v = mem.value;
    if (typeof v === "string") {
        return v.trim();
    }
    if (v !== null && typeof v === "object") {
        const raw = v.base;
        if (typeof raw === "string") {
            return raw.trim();
        }
        if (raw !== null && typeof raw === "object" &&
            typeof raw.value === "string") {
            return raw.value.trim();
        }
    }
    return String(v).trim();
}

function stage2ApplyCmp(context, site) {
    const s2 = stage2State();
    if (!s2.active || s2.sub !== 2) {
        return;
    }
    /* Counted before every other check: "cmp seen" is a compile-time count and
     * "cmpCandidates" is a post-match count, so without this the log cannot
     * distinguish "the callout never fired" from "it fired and every operand
     * check rejected it". */
    s2.applyRuns = (s2.applyRuns || 0) + 1;
    /* Refresh the reference value here, not at the guard landmark. The landmark
     * fires on the read of dec_lic + 0x33, which in the mimic target happens
     * before that word is written, so it still reads 0; by the time the
     * comparison executes the word holds the real value. Re-reading is
     * harmless in the real flow, where the decrypted buffer is already
     * complete and stable. */
    try {
        /* Never let a zero overwrite a known reference value. Reading the field
         * is a refresh, not a reset: when decLicBuf points somewhere the licence
         * does not live (round 28 re-pointed it at the read-only mapped file),
         * the read yields 0 and every site is refused for the wrong reason. */
        const fresh = s2.decLicBuf !== null
            ? s2.decLicBuf.add(HASH3_OFFSET).readU16()
            : s2.decLic.add(HASH3_OFFSET).readU16();
        if (fresh !== 0 || s2.hash3 === 0) {
            s2.hash3 = fresh;
        }
    } catch (e) {
        /* keep the previous value */
    }
    const base = String(site.memBase).trim();
    /* Existence is tested by indexing, not by hasOwnProperty. Frida's
     * CpuContext is a native object whose register fields are not own
     * properties -- Object.keys(context) is empty and hasOwnProperty is false
     * for every register -- so the hasOwnProperty form rejected a perfectly
     * good "rax" and reported it as noBase. Indexing is how the rest of the
     * agent reads registers (context[PC_REG]) and it works. */
    if (context[base] === undefined || context[base] === null) {
        s2.applyNoBase = (s2.applyNoBase || 0) + 1;
        if (s2.applyNoBase <= 3) {
            stage2Log("cmp-no-base", "pc=" + site.address +
                " memBase=\"" + base + "\" reg=" + site.regName);
        }
        return;
    }
    let memVal;
    try {
        memVal = context[base].readU16();
    } catch (e) {
        s2.applyBadRead = (s2.applyBadRead || 0) + 1;
        return;
    }
    const regName = String(site.regName).trim();
    const found = stage2RegValue(context, regName);
    if (found === null) {
        s2.applyNoReg = (s2.applyNoReg || 0) + 1;
        return;
    }
    const regVal = found.value.and(0xffff).toUInt32();

    /* Log before deciding.
     *
     * Round 41 put the zero-check first, so every site that was refused vanished
     * from the log as well and the round reported zero cmp-site lines for the
     * real samples -- indistinguishable from "no comparison executed". The log
     * must not be gated by the match logic; report the site, then apply the
     * rules. */
    s2.cmpSites = (s2.cmpSites || 0) + 1;
    if (s2.cmpSites <= 10) {
        /* Report where the reference value comes from, not just what it is.
         *
         * Every cmp-site in the unpacker showed ours=0x0 while stage2 start had
         * logged hash3=0x6501, so the reference value is being lost between
         * startStage2 and the first comparison. Without the source -- decLicBuf
         * set or not, which sub-stage we are in -- there is no way to tell which
         * of the two places that set s2.hash3 did it. */
        stage2Log("cmp-site", "#" + s2.cmpSites + " pc=" + site.address +
            " mem[" + base + "]=0x" + memVal.toString(16) + " " + regName +
            "=0x" + regVal.toString(16) + " ours=0x" +
            s2.hash3.toString(16) + " match=" +
            (memVal === s2.hash3 || regVal === s2.hash3) +
            " sub=" + s2.sub + " decLicBuf=" + s2.decLicBuf +
            " decLic=" + s2.decLic);
    }

    /* Never key the match on zero.
     *
     * Round 40 reached stage2 complete on a real sample three times, but every
     * one of them matched with ours=0x0: the reference value had been clobbered
     * to zero by the time the site executed, and "the register operand is zero"
     * matches any comparison that loads a zero -- which is common and proves
     * nothing. Re-read hash_3 from the buffer here, and refuse to match when it
     * is still zero. */
    if (s2.hash3 === 0 && s2.decLicBuf !== null) {
        try {
            s2.hash3 = s2.decLicBuf.add(HASH3_OFFSET).readU16();
        } catch (e) {
            /* leave it; the zero check below will refuse the match */
        }
    }
    if (s2.hash3 === 0) {
        s2.applyNoOurs = (s2.applyNoOurs || 0) + 1;
        return;
    }

    s2.cmpCandidates++;
    if (s2.cmpCandidates <= 4) {
        stage2Log("cmp-candidate", "pc=" + site.address + " mem[" + base +
            "]=" + memVal.toString(16) + " " + regName + "=0x" +
            regVal.toString(16) + " ours=0x" + s2.hash3.toString(16));
    }
    /* Census of distinct comparison sites.
     *
     * The first-ten log only ever showed the same site (pc=0x140371b85, the
     * byte-by-byte comparison of the path string "C:\Program"), which cannot
     * distinguish "the hash_3 comparison never runs" from "it runs and this
     * matcher does not recognise it". Logging the first occurrence of each
     * distinct pc, with its operands, answers that in one round. */
    s2.pcsSeen = s2.pcsSeen || {};
    if (!s2.pcsSeen[site.address]) {
        s2.pcsSeen[site.address] = 1;
        s2.pcCount = (s2.pcCount || 0) + 1;
        if (s2.pcCount <= 30) {
            let text = "?";
            try {
                text = Instruction.parse(ptr(site.address)).toString();
            } catch (e) {
                /* leave the marker */
            }
            stage2Log("cmp-pc", "#" + s2.pcCount + " pc=" + site.address +
                " mem[" + base + "]=0x" + memVal.toString(16) + " " + regName +
                "=0x" + regVal.toString(16) + " ours=0x" +
                s2.hash3.toString(16) + " insn=" + text);
        }
    }

    /* Exactly one operand is the hash_3 we generated; the other is what the
     * program expects. Same rule as stage2.cpp's find_hash_cmp. */
    let expected = null;
    let oursIsMem = false;
    if (memVal !== s2.hash3) {
        if (regVal !== s2.hash3) {
            return;
        }
        expected = memVal;
    } else {
        expected = regVal;
        oursIsMem = true;
    }

    s2.realHash3 = expected;
    s2.cmpAddress = site.address;
    s2.sub = 3;
    stage2Log("hash3-found", "hash_3=" + expected + " (0x" +
        expected.toString(16) + ") ours=0x" + s2.hash3.toString(16) +
        " oursIsMem=" + oursIsMem);

    if (oursIsMem) {
        context[base].writeU16(expected);
        stage2Log("bypass", "[" + base + "] <- 0x" + expected.toString(16));
    } else {
        /* Write the expected value through the register operand's parent.
         *
         * `parent` was never defined in this scope: the write threw, the
         * caller's catch swallowed it, and the run ended with hash3-found and
         * no bypass at all (round 24, the first real sample to get this far:
         * mem[rsi]=0x43 r10w=0x0 ours=0x0, then silence). WORD_REGISTERS
         * already maps r10w -> r10; use it, and say so if the name is missing
         * instead of failing silently again. */
        const writeName = stage2RegWriteName(context, regName);
        if (writeName === null) {
            stage2Log("bypass-no-register", "reg=" + regName);
            return;
        }
        const upper = context[writeName].and(ptr(0xffff).not());
        context[writeName] = upper.or(ptr(expected & 0xffff));
        stage2Log("bypass", writeName + " <- 0x" + expected.toString(16));
    }
    s2.neutralised++;
    stage2Unfollow();
    stage2Log("complete", "advance(dec_lic=" + s2.decLic + ")");
    emit({ spike: "stage2_complete", hash3: expected,
           decLic: s2.decLic.toString(), cmpSite: site.address });
}

function isSystemModule(module) {
    /* Windows system DLLs, and on Linux the C runtime: both run natively so
     * the trace stays affordable. Everything else -- the main image and the
     * protector's own allocations alike -- is traced. */
    const path = (module.path || "").toLowerCase();
    if (path.indexOf("\\windows\\") !== -1) {
        return true;
    }
    if (path.indexOf("/lib/") !== -1 || path.indexOf("/lib64/") !== -1) {
        return true;
    }
    if (path.indexOf("ld-linux") !== -1 || path.indexOf("libc.so") !== -1) {
        return true;
    }
    return false;
}

function isSystemAddress(address) {
    /* "Not a system module", never "the main module": the protection's own
     * code (and therefore both the license copy and the hash_3 comparison)
     * frequently runs in memory the protector allocated for itself, which
     * Process.findModuleByAddress reports as null. Requiring the main module
     * dropped every byte-store candidate on VPIplayer.exe (0 candidates from
     * 85k byte stores) while the same gate had already been proven wrong for
     * Stage 1's landmark. */
    for (let i = 0; i < plan.systemRanges.length; i++) {
        const range = plan.systemRanges[i];
        if (address.compare(range[0]) >= 0 && address.compare(range[1]) < 0) {
            return true;
        }
    }
    return false;
}

function install(iterator) {
    let insn;
    while ((insn = iterator.next()) !== null) {
        stats.instructions++;
        /* Tick from inside the transform.
         *
         * Round 29 completed stage 1 eight times, armed the guard 8/8, opened the
         * window 8/8 -- and then produced no cmp-site, no summary and not even the
         * +3s heartbeat, which means the JS thread stopped servicing timers right
         * after "following". The only other JS work is this transform, and a
         * transform entered in a tight loop starves the event loop. This tick is
         * emitted from the transform itself, so it keeps arriving even if the
         * timers are starved -- which is exactly the distinction to make. */
        if (stats.instructions % 20000 === 0) {
            stage2Log("scan-tick", "instructions=" + stats.instructions +
                " inside=" + stats.inside + " outside=" + stats.outside +
                " cmp=" + (plan.stage2 ? (plan.stage2.scanCmp || 0) : 0));
        }
        const address = insn.address;
        if (address.compare(plan.moduleEnd) >= 0 ||
            address.compare(plan.moduleBase) < 0) {
            stats.outside++;
        } else {
            stats.inside++;
        }
        const system = isSystemAddress(address);
        /* 1-byte memory destination = a byte store (or read-modify-write). */
        const first = insn.operands.length > 0 ? insn.operands[0] : null;
        if (first !== null && first.type === "mem" && first.size === 1) {
            if (system) {
                stats.byteStoresSystem++;
            } else {
                const info = snapshot(insn);
                stats.byteStoresPlanned++;
                iterator.putCallout(function (context) {
                    try {
                        recordCandidate(info, context);
                    } catch (e) {
                        /* never let a callout kill the trace */
                    }
                });
            }
        }

        /* Stage 1 does NOT instrument reads or calls. A callout on every
         * memory read costs ~100x what PIN's native instrumentation costs:
         * measured 500k callouts fired in a few seconds on drchost, which
         * slows the protection's own unpacking so much that the RSA path is
         * minutes away instead of seconds. Sub-stage 1 uses a guard page
         * (exception handler) and sub-stages 3/4 a static call scan, both of
         * which leave the target running at native speed until it touches
         * what we care about. */
        /* Stage 2 sub-stage 2 needs the comparison, which reads a register
         * rather than dec_lic, so its callout is emitted into every block from
         * the start and decides at run time whether to do anything. Gating
         * this at compile time instead was the bug: the comparison's block was
         * compiled during Stage 0, when Stage 2 was not yet active, so it
         * carried no callout at all and Stalker.flush() could not repair a
         * block that had not changed. */
        if (plan.stage2 !== undefined && plan.stage2.active && !system) {
            const site = stage2RecogniseCmp(insn);
            if (site !== null) {
                iterator.putCallout(function (context) {
                    if (plan.stage2.sub !== 2) {
                        return;
                    }
                    try {
                        stage2ApplyCmp(context, site);
                    } catch (e) {
                        /* never let a callout kill the trace */
                    }
                });
            }
        }
        /* PIN's Stage 1 does not guess a return address: it waits for the next
         * direct call executed after the license read and takes its
         * destination as mp_exptmod (wl-extract stage1.cpp::process_ins). On
         * x86 VPIplayer all six hooked return-address candidates went
         * unreached, so port the mechanism itself rather than the guess.
         * The callout is emitted for every direct call but returns on its
         * first line until the landmark has been taken, and gives up after a
         * few tries -- the expensive part (the argument fingerprint) only runs
         * for those few. */
        if (plan.callWatch && insn.mnemonic === "call" && !system) {
            let dest = null;
            try {
                if (Memory.readU8(address) === 0xE8) {
                    const rel = Memory.readS32(address.add(1));
                    dest = address.add(5 + rel);
                }
            } catch (e) {
                dest = null;
            }
            if (dest !== null) {
                const site = { address: address.toString(), dest: dest };
                iterator.putCallout(function (context) {
                    const stage1 = plan.stage1;
                    if (stage1 === undefined || !stage1.landmarkSeen ||
                        stage1.path === "ret") {
                        return;
                    }
                    /* The callout is emitted for every direct call in every
                     * non-system module, on every followed thread, so the
                     * first calls after the read belong to whichever thread
                     * gets there first (round 13: x64 ngahost#7 spent all
                     * five attempts on 0x7fff0ac64850, 0x7fff0ac65490, ...,
                     * none of them RSA). PIN does not have this problem:
                     * process_ins is tied to the reading thread's instruction
                     * stream.
                     *
                     * Filter by stack instead of by thread id.
                     * Process.getCurrentThreadId() is not usable here: inside
                     * the exception handler that takes the landmark it reports
                     * the agent's own thread, not the faulting one, so
                     * comparing it against this callout's thread filtered out
                     * *every* call (round 14: zero call-watch lines). The RSA
                     * call is a call from the frame that read the license, so
                     * its stack pointer is close to the landmark's; another
                     * thread's stack is megabytes away. */
                    if (stage1.landmarkSp !== null) {
                        const spNow = context[SP_REG];
                        const spLand = stage1.landmarkSp;
                        if (spNow.compare(spLand.add(0x20000)) > 0 ||
                            spLand.compare(spNow.add(0x20000)) > 0) {
                            return;
                        }
                    }
                    if (!stage1.mpExptmod) {
                        /* Still looking for the RSA call: the fingerprint only
                         * runs for the first few candidates after the read. */
                        if (stage1.callWatchTries >= 12) {
                            return;
                        }
                    } else if (site.dest.toString() !== stage1.mpExptmod) {
                        /* Identified: only its own call sites are interesting,
                         * so the expensive fingerprint is skipped for every
                         * other call in the process. */
                        return;
                    }
                    try {
                        stage1CallWatch(context, site);
                    } catch (e) {
                        /* never let a callout kill the trace */
                    }
                });
            }
        }

        iterator.keep();
    }
}

/* ---------------------------------------------------------------- Windows */

function installWindowsHooks() {
    const ntdll = "ntdll.dll";
    const kernel32 = "kernel32.dll";

    plan.redirectBuffer = Memory.allocUtf16String(plan.ntPath);
    const nameOffset = PTR_SIZE === 8 ? 0x10 : 0x8;
    const bufferOffset = PTR_SIZE === 8 ? 0x8 : 0x4;
    /* RootDirectory is the second field of OBJECT_ATTRIBUTES. Our replacement
     * path is always absolute (\??\...), and the object manager rejects an
     * absolute ObjectName combined with a non-NULL RootDirectory with
     * STATUS_INVALID_PARAMETER (CreateFile -> error 87). That is exactly what
     * happens when the target opens a *relative* "regkey.dat": kernel32 sets
     * RootDirectory to the current directory handle. Zero it. */
    const rootOffset = PTR_SIZE === 8 ? 0x8 : 0x4;

    const createFileHook = function (callSite) {
        return function (args) {
            const objectAttributes = args[2];
            if (objectAttributes.isNull()) {
                return;
            }
            const objectName = objectAttributes.add(nameOffset).readPointer();
            if (objectName.isNull()) {
                return;
            }
            const length = objectName.readU16();
            const buffer = objectName.add(bufferOffset).readPointer();
            if (buffer.isNull() || length === 0) {
                return;
            }
            let path = "";
            try {
                path = buffer.readUtf16String(length / 2);
            } catch (e) {
                return;
            }
            stats.fileOpens++;
            /* Record what the target actually opens: with a real sample the
             * first question is whether it looks for a license file at all,
             * and under which name. */
            if (report.openedPaths.length < 80 &&
                report.openedPaths.indexOf(path) < 0) {
                report.openedPaths.push(path);
            }
            if (path.slice(-10).toLowerCase() !== "regkey.dat") {
                return;
            }
            report.originalLicensePath = path;
            plan.mainThread = Process.getCurrentThreadId();
            report.mainThread = plan.mainThread;
            report.redirectedVia = callSite;
            stats.redirects++;
            const previousRoot = objectAttributes.add(rootOffset)
                .readPointer();
            objectName.writeU16(plan.ntPath.length * 2);
            objectName.add(2).writeU16((plan.ntPath.length + 1) * 2);
            objectName.add(bufferOffset).writePointer(plan.redirectBuffer);
            if (!previousRoot.isNull()) {
                objectAttributes.add(rootOffset).writePointer(ptr(0));
                report.clearedRootDirectory =
                    (report.clearedRootDirectory || 0) + 1;
            }
            emit({
                spike: "redirect",
                via: callSite,
                original: path,
                replacement: plan.ntPath,
                thread: plan.mainThread
            });
        };
    };

    for (const exportName of ["NtCreateFile", "ZwCreateFile"]) {
        const address = Module.findExportByName(ntdll, exportName);
        if (address === null) {
            report.errors.push(exportName + " not found");
            continue;
        }
        plan.hooks.push(Interceptor.attach(address,
            { onEnter: createFileHook(exportName) }));
    }

    const mapView = Module.findExportByName(kernel32, "MapViewOfFile");
    if (mapView !== null) {
        plan.hooks.push(Interceptor.attach(mapView, {
            onLeave: function (retval) {
                stats.maps++;
                if (headMatches(retval)) {
                    plan.licMapped = true;
                    plan.mapAddress = retval.toString();
                    report.licenseMappedTo = retval.toString();
                    emit({ spike: "lic_mapped", addr: retval.toString() });
                    if (!plan.tracing) {
                        /* startTracing is an rpc export; call it through the
                         * same code path by hand to avoid re-entrancy. */
                        plan.tracing = true;
                        followStart = Date.now();
                        /* Follow every thread again.
                         *
                         * Restricting this to the licence-mapping thread was a
                         * Stage 2 measure: the Stalker window costs a JS callback
                         * per instruction and saturated the JS thread. Stage 2 no
                         * longer uses a window (it uses a data breakpoint on the
                         * hash_3 field), so that cost is gone -- and Stage 1's
                         * mechanism *is* the transform: sub4-found-mp_exptmod and
                         * the licence-page reads both come from it. Cutting this
                         * to one thread is why tracing_started_at_map went from
                         * threads=4/5 to threads=1 and why rounds 33-37 produced
                         * guard-hit 0-3 and no Stage 1 completion at all. */
                        const candidates = plan.noTrace
                            ? []
                            : Process.enumerateThreads();
                        if (plan.noTrace) {
                            emit({ spike: "tracing_started_at_map",
                                   threads: 0, skipped: "noTrace" });
                        }
                        for (const thread of candidates) {
                            try {
                                Stalker.follow(thread.id,
                                               { transform: install });
                                plan.followed.push(thread.id);
                            } catch (e) {
                                report.errors.push("follow " + thread.id +
                                                   ": " + String(e));
                            }
                        }
                        report.followedThreads = plan.followed;
                        emit({ spike: "tracing_started_at_map",
                               threads: plan.followed.length });
                    }
                }
            }
        }));
    } else {
        report.errors.push("MapViewOfFile not found");
    }

    const unmapView = Module.findExportByName(kernel32, "UnmapViewOfFile");
    if (unmapView !== null) {
        plan.hooks.push(Interceptor.attach(unmapView, {
            onEnter: function (args) {
                if (!plan.licMapped) {
                    return;
                }
                if (!headMatches(args[0])) {
                    return;
                }
                plan.licMapped = false;
                resolveCopy(args[0].toString(), "UnmapViewOfFile");
            }
        }));
    }

    /* Does the protection leave the process inside the RSA call?
     *
     * Stage 2 arms a guard on the decrypted buffer and waits for the hash_3
     * read. Rounds 21/22 armed it on every real completion and it was never
     * hit, and the refresh that re-resolves the buffer never ran either -- not
     * from the 20ms timer and not from the mp_exptmod hook's onLeave. That is
     * exactly what it looks like if the process never comes back from that
     * call. Logging the exit and its caller separates "the target died inside
     * the call" from "the comparison happens inside the call, so arming after
     * it is too late". */
    for (const exportName of ["ExitProcess", "TerminateProcess",
                              "RtlExitUserProcess"]) {
        let exitAddress = Module.findExportByName(kernel32, exportName);
        if (exitAddress === null) {
            exitAddress = Module.findExportByName("ntdll.dll", exportName);
        }
        if (exitAddress === null) {
            continue;
        }
        try {
            plan.hooks.push(Interceptor.attach(exitAddress, {
                onEnter: function () {
                    let caller = "?";
                    try {
                        caller = this.returnAddress.toString();
                    } catch (e) {
                        /* keep the marker */
                    }
                    stage1Log("target-exit", exportName + " from " + caller);
                }
            }));
        } catch (e) {
            stage1Log("target-exit-hook-failed", exportName + ": " + String(e));
        }
    }

    if (unmapView === null) {
        report.errors.push("UnmapViewOfFile not found");
    }
}

/* ---------------------------------------------------- diagnostic hooks --- */

/* Why this exists: when Stage 1 never takes its landmark, the question is
 * always "did the program reach the license verification at all, or is it
 * stuck earlier?" A dialog answers that directly. WinLicense reports a
 * rejected license with a MessageBox, so a logged message box means the
 * license path ran to completion; no message box at all means the program
 * never got there and the problem is upstream (anti-VM probing, a missing
 * dependency, or a blocked initialisation step).
 *
 * ExitProcess/TerminateProcess are logged for the same reason: a process
 * that leaves on its own is telling us it gave up.
 */
function installDiagnosticHooks() {
    const boxes = [["user32.dll", "MessageBoxA", false],
                   ["user32.dll", "MessageBoxW", true]];
    for (const [mod, name, wide] of boxes) {
        let address = null;
        try {
            address = Module.getExportByName(mod, name);
        } catch (e) {
            continue;
        }
        if (address === null) {
            continue;
        }
        try {
            plan.hooks.push(Interceptor.attach(address, {
                onEnter: function (args) {
                    try {
                        const text = wide
                            ? args[1].readUtf16String()
                            : args[1].readAnsiString();
                        const caption = wide
                            ? args[2].readUtf16String()
                            : args[2].readAnsiString();
                        plan.messageBoxes = (plan.messageBoxes || 0) + 1;
                        emit({ spike: "messagebox", fn: name,
                               caption: caption, text: text });
                    } catch (e) {
                        emit({ spike: "messagebox", fn: name,
                               error: String(e) });
                    }
                }
            }));
        } catch (e) {
            report.errors.push("hook " + name + ": " + String(e));
        }
    }

    const exits = [["kernel32.dll", "ExitProcess"],
                   ["kernel32.dll", "TerminateProcess"]];
    for (const [mod, name] of exits) {
        let address = null;
        try {
            address = Module.getExportByName(mod, name);
        } catch (e) {
            continue;
        }
        if (address === null) {
            continue;
        }
        try {
            plan.hooks.push(Interceptor.attach(address, {
                onEnter: function (args) {
                    emit({ spike: "exit", fn: name,
                           code: args[0].toString() });
                }
            }));
        } catch (e) {
            report.errors.push("hook " + name + ": " + String(e));
        }
    }
}

function installLinuxHooks() {
    const libc = "libc.so.6";
    const mmapAddr = Module.findExportByName(libc, "mmap") ||
        Module.findExportByName(null, "mmap");
    const munmapAddr = Module.findExportByName(libc, "munmap") ||
        Module.findExportByName(null, "munmap");
    if (mmapAddr !== null) {
        plan.hooks.push(Interceptor.attach(mmapAddr, {
            onLeave: function (retval) {
                stats.maps++;
                if (headMatches(retval)) {
                    plan.licMapped = true;
                    plan.mapAddress = retval.toString();
                    report.licenseMappedTo = retval.toString();
                    emit({ spike: "lic_mapped", addr: retval.toString() });
                    if (!plan.tracing) {
                        /* startTracing is an rpc export; call it through the
                         * same code path by hand to avoid re-entrancy. */
                        plan.tracing = true;
                        followStart = Date.now();
                        /* Follow every thread again.
                         *
                         * Restricting this to the licence-mapping thread was a
                         * Stage 2 measure: the Stalker window costs a JS callback
                         * per instruction and saturated the JS thread. Stage 2 no
                         * longer uses a window (it uses a data breakpoint on the
                         * hash_3 field), so that cost is gone -- and Stage 1's
                         * mechanism *is* the transform: sub4-found-mp_exptmod and
                         * the licence-page reads both come from it. Cutting this
                         * to one thread is why tracing_started_at_map went from
                         * threads=4/5 to threads=1 and why rounds 33-37 produced
                         * guard-hit 0-3 and no Stage 1 completion at all. */
                        const candidates = plan.noTrace
                            ? []
                            : Process.enumerateThreads();
                        if (plan.noTrace) {
                            emit({ spike: "tracing_started_at_map",
                                   threads: 0, skipped: "noTrace" });
                        }
                        for (const thread of candidates) {
                            try {
                                Stalker.follow(thread.id,
                                               { transform: install });
                                plan.followed.push(thread.id);
                            } catch (e) {
                                report.errors.push("follow " + thread.id +
                                                   ": " + String(e));
                            }
                        }
                        report.followedThreads = plan.followed;
                        emit({ spike: "tracing_started_at_map",
                               threads: plan.followed.length });
                    }
                }
            }
        }));
    } else {
        report.errors.push("mmap not found");
    }
    if (munmapAddr !== null) {
        plan.hooks.push(Interceptor.attach(munmapAddr, {
            onEnter: function (args) {
                if (!plan.licMapped) {
                    return;
                }
                if (!headMatches(args[0])) {
                    return;
                }
                plan.licMapped = false;
                resolveCopy(args[0].toString(), "munmap");
            }
        }));
    } else {
        report.errors.push("munmap not found");
    }
}

/* Search the recorded candidates for the address that now holds the license
 * head — the same test the PIN tool runs after the unmap. */
/* Find the licence copy by its content, with no help from the transform.
 *
 * The byte-wise write tracking that fills plan.copySet only exists because the
 * transform sees every instruction. With UNLICENSE_GUARD_NO_TRACE the set is
 * empty and Stage 0 cannot resolve at all (round 50: no lic_copy, no guard, no
 * Stage 1). The licence head is known from setup, so scan for it instead -- the
 * same trick stage2LocateBufferByContent already uses for the decrypted buffer. */
function scanForHead() {
    const hits = [];
    let ranges = [];
    try {
        ranges = Process.enumerateRanges("rw-");
    } catch (e) {
        return hits;
    }
    const pattern = plan.head
        .map(function (byte) {
            return byte.toString(16).padStart(2, "0");
        })
        .join(" ");
    for (let i = 0; i < ranges.length && hits.length < 8; i++) {
        const range = ranges[i];
        if (range.size > 0x4000000) {
            continue;
        }
        try {
            const found = Memory.scanSync(range.base, range.size, pattern);
            for (let j = 0; j < found.length && hits.length < 8; j++) {
                hits.push(found[j].address.toString());
            }
        } catch (e) {
            /* unreadable range */
        }
    }
    return hits;
}

function resolveCopy(unmappedAddress, via) {
    let candidates = Object.keys(plan.copySet);
    if (candidates.length === 0) {
        emit({ spike: "copy-scan", event: "no-tracked-candidates" });
        candidates = scanForHead();
        emit({ spike: "copy-scan", event: "content-hits",
               count: candidates.length,
               hits: candidates.slice(0, 4) });
    }
    report.candidates = candidates.length;
    report.unmapped = unmappedAddress;
    for (const candidate of candidates) {
        const address = ptr(candidate);
        if (headMatches(address)) {
            plan.licCopy = candidate;
            report.licCopy = candidate;
            report.licCopyFirstBytes = hex(
                new Uint8Array(address.readByteArray(HEAD_LEN)));
            emit({
                spike: "lic_copy",
                via: via,
                addr: candidate,
                candidates: candidates.length,
                bytes: report.licCopyFirstBytes
            });
            startStage1(candidate);
            return;
        }
    }
    report.licCopy = null;
    emit({
        spike: "lic_copy_missing",
        via: via,
        candidates: candidates.length
    });
}

/* ======================================================================
 * Stage 1 -- RSA bypass (port of wl-extract/staging/stage1.cpp)
 *
 * Sub-stage chain, all driven from read/call callouts:
 *   1  first read whose EA == lic_copy (= inside mp_read_unsigned_bin)
 *      -> ret_to_rsaexptmod = [esp+8]
 *   2  execution reaches that address (back inside rsa_exptmod)
 *      -> dec_lic = [esp+0x8c], key_tmp_ref = ebp+0x1c
 *   3  the second read at key_tmp_ref -> the next call is mp_exptmod
 *   4  first direct (E8) call -> its destination is mp_exptmod
 *   5  at mp_exptmod's entry: swap the key pointers for the first
 *      dec_sections calls (decrypt), then for the verify call
 *   6  done: dec_lic is the RSA-decrypted license buffer (Stage 2 input)
 *
 * x86 reads the arguments off the stack; x64 keeps them in registers, so
 * both slot kinds are supported and the mapping is configurable.
 * ====================================================================== */

function stage1Log(event, detail) {
    emit({ spike: "stage1", event: event, detail: detail });
}

/* libtommath mp_int on the target: { int used; int alloc; int sign; mp_digit *dp; } */
function buildMpInt(hexDigits, digitCount) {
    /* digitCount 32-bit digits = digitCount * 4 bytes = digitCount * 8 hex
     * characters. Walk the hex string one byte at a time: the previous loop
     * advanced the byte index by 2 and then indexed the hex string with it,
     * which both skipped every other byte and read the wrong pairs, so the
     * key it swapped in was never the key it claimed to build. */
    const byteCount = digitCount * 4;
    const digits = Memory.alloc(byteCount);
    for (let i = 0; i < byteCount; i++) {
        digits.add(i).writeU8(parseInt(hexDigits.substr(i * 2, 2), 16));
    }
    /* dp sits at 12 on x86 and 16 on x64 (see mpIntDpOffset), so the struct
     * needs the extra room or the pointer write runs past the end. */
    const mp = Memory.alloc(mpIntDpOffset() + Process.pointerSize);
    mp.writeS32(digitCount);          /* used  */
    mp.writeS32(digitCount);          /* alloc */
    mp.writeS32(0);                   /* sign = MP_ZPOS */
    mp.add(mpIntDpOffset()).writePointer(digits);  /* dp */
    return { struct: mp, digits: digits };
}

/* An mp_int holding 1.
 *
 * Swapping this in as mp_exptmod's exponent turns the "decryption" into the
 * identity: base^1 mod P = base (for base < P), so the buffer the protection
 * decrypts into holds exactly the bytes we put in the licence file. That
 * replaces the plaintext lottery -- rounds 24/26/27 reached the hash comparison
 * on 1 completion in 5, because the garbage the swapped modulus produced only
 * sometimes got past the protection's earlier checks -- with content we choose,
 * which is the precondition for working out what it accepts. */
function buildMpIntOne() {
    const digits = Memory.alloc(4);
    digits.writeU32(1);
    const mp = Memory.alloc(mpIntDpOffset() + Process.pointerSize);
    mp.writeS32(1);                   /* used  */
    mp.writeS32(1);                   /* alloc */
    mp.writeS32(0);                   /* sign = MP_ZPOS */
    mp.add(mpIntDpOffset()).writePointer(digits);
    return { struct: mp, digits: digits };
}

function stage1KeyMaterial() {
    const stage1 = plan.stage1;
    if (stage1.mpInts !== null || plan.rsaKeys === null) {
        return stage1.mpInts;
    }
    stage1.mpInts = {
        key1: {
            exp: buildMpInt(plan.rsaKeys.exp1, plan.rsaKeys.exp1Len),
            mod: buildMpInt(plan.rsaKeys.mod1, plan.rsaKeys.mod1Len)
        },
        key2: {
            exp: plan.identityKey
                ? buildMpIntOne()
                : buildMpInt(plan.rsaKeys.exp2, plan.rsaKeys.exp2Len),
            mod: buildMpInt(plan.rsaKeys.mod2, plan.rsaKeys.mod2Len)
        }
    };
    stage1Log("keys-materialised",
        "key1 exp=" + stage1.mpInts.key1.exp.struct +
        " mod=" + stage1.mpInts.key1.mod.struct +
        " key2 exp=" + stage1.mpInts.key2.exp.struct +
        " mod=" + stage1.mpInts.key2.mod.struct +
        (plan.identityKey ? " identityKey=true" : ""));
    return stage1.mpInts;
}

function slotRead(context, slot) {
    if (slot.kind === "reg") {
        return context[slot.name];
    }
    return context[SP_REG].add(slot.offset).readPointer();
}

function slotWrite(context, slot, value) {
    if (slot.kind === "reg") {
        context[slot.name] = value;
        return;
    }
    context[SP_REG].add(slot.offset).writePointer(value);
}

/* Describe an mp_int the target passed in, so the first run tells us which
 * argument is the exponent and which is the modulus. */
/* Offset of the digit pointer inside libtommath's mp_int.
 *
 *   struct { int used, alloc, sign; mp_digit *dp; }
 *
 * On x86 the three ints are 12 bytes and dp follows immediately at 12. On
 * x64 the pointer needs 8-byte alignment, so four bytes of padding are
 * inserted and dp lands at 16. Hardcoding 12 (as the first version did)
 * makes every argument on x64 fail the shape check and read as garbage --
 * 'access violation accessing 0xffffffffffffffff' while dereferencing dp. */
function mpIntDpOffset() {
    return Process.pointerSize === 4 ? 12 : 16;
}

function describeMpInt(pointer) {
    if (pointer.isNull()) {
        return "null";
    }
    try {
        const used = pointer.readS32();
        const alloc = pointer.readS32();
        const sign = pointer.readS32();
        const dp = pointer.add(mpIntDpOffset()).readPointer();
        const digits = [];
        for (let i = 0; i < Math.min(used, 4); i++) {
            digits.push(dp.add(i * 4).readU32().toString(16));
        }
        return "{used:" + used + ",alloc:" + alloc + ",sign:" + sign +
            ",dp:" + dp + ",digits:[" + digits.join(",") + "]}";
    } catch (e) {
        return "{unreadable: " + String(e) + "}";
    }
}

function stage1MpExptmodEnter(context) {
    const stage1 = plan.stage1;
    stage1.callCount++;
    const slots = plan.stage1KeySlots;
    const observed = [];
    for (let i = 0; i < slots.length; i++) {
        observed.push("arg" + i + "(" + (slots[i].kind === "reg"
            ? slots[i].name : "esp+" + slots[i].offset) + ")=" +
            describeMpInt(slotRead(context, slots[i])));
    }
    if (!stage1.firstSwapLogged) {
        stage1.firstSwapLogged = true;
        stage1Log("mp_exptmod-enter", "call#" + stage1.callCount +
            " dec_sections=" + stage1.decSections + " | " +
            observed.join(" | "));
    }
    const keys = stage1KeyMaterial();
    if (keys === null) {
        return;
    }
    if (stage1.callCount < stage1CallThreshold(stage1)) {
        slotWrite(context, slots[0], keys.key2.exp.struct);
        slotWrite(context, slots[1], keys.key2.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- rsa_key_2");
    } else {
        const finalKey = stage1FinalKey(keys);
        slotWrite(context, slots[0], finalKey.exp.struct);
        slotWrite(context, slots[1], finalKey.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- " +
            (plan.stage1CompleteAfter > 0 ? "rsa_key_2" : "rsa_key_1"));
        disarmGuard();
        stage1.sub = 6;
        report.stage1DecLic = stage1.decLic;
        report.stage1Complete = true;
        stage1Log("complete", "dec_lic=" + stage1.decLic +
            " (RSA-decrypted license buffer, Stage 2 input)");
        /* Hand the decrypted buffer to Stage 2, which keys on the 2-byte
         * read of dec_lic + 0x33 (stage2.cpp's stage2::init). */
        if (stage1.decLic !== null && stage1.decLic !== undefined) {
            stage1Log("stage2-handoff", "decLic=" + stage1.decLic);
            try {
                startStage2(stage1.decLic);
                stage1Log("stage2-armed", "sub=" + plan.stage2.sub);
                /* The output mp_int is still empty at this point (we are inside
                 * the call's onEnter); re-resolve its digit buffer once the RSA
                 * write has happened. See stage2RefreshBuffer. */
                setTimeout(stage2RefreshBuffer, 20);
                /* Locate the decrypted buffer by its contents: the
                 * argument-derived addresses have been ruled out (rounds
                 * 31/33). Runs on the JS thread -- scanning memory inside the
                 * hook would stall it. */
                setTimeout(stage2LocateBufferByContent, 25);
            } catch (e) {
                stage1Log("stage2-start-failed", String(e));
            }
        } else {
            stage1Log("stage2-skipped", "decLic=" + stage1.decLic);
        }
    }
}


/* Fired by a callout on every direct (E8) call while sub-stage 4 is armed. */

/* Sub-stage 2: execution is back inside rsa_exptmod. The destination buffer
 * for the RSA-decrypted license is an argument of this frame, at a
 * build-specific offset (the PIN original uses [esp+0x8c]); every candidate
 * slot is logged so the right one can be pinned down, and the first heap
 * pointer found is used. */
function stage1BackInRsaExptmod(context) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 2) {
        return;
    }
    const sp = context[SP_REG];
    const observed = [];
    let chosen = null;
    for (const offset of plan.decLicCandidates) {
        let value = null;
        let writable = false;
        let onStack = false;
        try {
            value = sp.add(offset).readPointer();
            const range = Process.findRangeByAddress(value);
            writable = range !== null && range.protection.indexOf("w") >= 0;
            onStack = value.compare(sp) >= 0 &&
                value.compare(sp.add(0x20000)) < 0;
        } catch (e) {
            /* unreadable slot */
        }
        if (value !== null) {
            observed.push("[sp+" + offset.toString(16) + "]=" + value +
                (writable ? " w" : "") + (onStack ? " stack" : ""));
            if (chosen === null && writable && !onStack) {
                chosen = value;
            }
        }
    }
    stage1.decLic = chosen !== null ? chosen.toString() : null;
    stage1Log("sub2-back-in-rsaexptmod", "pc=" + context[PC_REG] +
        " dec_lic=" + stage1.decLic + " frame: " + observed.join(" "));

    /* Validate the candidate before committing to it. Several stack slots hold
     * code addresses, only one of them returns into rsa_exptmod, and hooking
     * the wrong one silently produces garbage: ngahost#2/#6 reached sub-stage 2
     * with pc=0x140237d16, dec_lic=null, an all-garbage frame, and
     * "0 direct calls in the function" -- a real rsa_exptmod always contains
     * the direct call to mp_exptmod. Reject and stay in sub-stage 2 so the next
     * hooked candidate gets its turn. */
    const destinations = stage1ScanCalls(ptr(stage1.retToRsa), false);
    if (destinations.length === 0) {
        stage1.rejectedCandidates = (stage1.rejectedCandidates || 0) + 1;
        stage1Log("sub2-reject", "pc=" + context[PC_REG] + " retToRsa=" +
            stage1.retToRsa + " dec_lic=" + stage1.decLic +
            " no direct calls -- not rsa_exptmod, waiting for another " +
            "candidate (rejected " + stage1.rejectedCandidates + ")" +
            " [parsed=" + stage1ScanCalls.lastParsed +
            " first=" + stage1ScanCalls.lastFirst +
            " err=" + stage1ScanCalls.lastError + "]");
        stage1.sub = 2;
        return;
    }
    stage1.sub = 3;

    /* Sub-stages 3-5 in one step: scan this function's code for direct calls
     * and hook each destination; the RSA call is recognised by its arguments
     * being libtommath mp_ints of the expected digit counts. */
    stage1Log("sub3-call-candidates", destinations.length +
        " direct calls in the function: " +
        destinations.slice(0, 12).map(function (address) {
            return address.toString();
        }).join(" "));
    for (const destination of destinations) {
        /* Attach synchronously. The original wrapped this in
         * setTimeout(..., 0), which is the wrong tool here: we are inside an
         * Interceptor onEnter on the target thread (not a Stalker callout and
         * not the exception handler), and rsa_exptmod calls mp_exptmod
         * immediately after the read that got us here -- so a deferred attach
         * loses the first call and, with it, the whole key-swap sequence
         * (observed `calls=2` against `dec_sections=3`, completion branch
         * unreachable). Keep the timeout only as a fallback. */
        try {
            plan.hooks.push(Interceptor.attach(destination, {
                onEnter: function () {
                    try {
                        stage1CallCandidate(this.context, destination);
                    } catch (e) {
                        stage1Log("candidate-error", String(e));
                    }
                },
                onLeave: function () {
                    /* Logged a few times only. It answered its question in
                     * round 23 (the target does come back from the call), and
                     * unconditional logging then produced 349,660 lines and a
                     * 29MB job log in round 25. */
                    plan.stage1.leaveLogs = (plan.stage1.leaveLogs || 0) + 1;
                    if (plan.stage1.leaveLogs <= 3) {
                        stage1Log("sub4-leave", "returned from " + destination);
                    }
                    try {
                        stage2RefreshBuffer();
                    } catch (e) {
                        /* stage2RefreshBuffer reports its own failures */
                    }
                }
            }));
            stage1Log("sub3-hooked-sync", destination.toString());
        } catch (e) {
            stage1Log("candidate-hook-failed", String(e) + " for " +
                destination);
            setTimeout(function () {
                try {
                    plan.hooks.push(Interceptor.attach(destination, {
                        onEnter: function () {
                            try {
                                stage1CallCandidate(this.context, destination);
                            } catch (err) {
                                stage1Log("candidate-error", String(err));
                            }
                        },
                        onLeave: function () {
                            try {
                                stage2RefreshBuffer();
                            } catch (err) {
                                /* reported inside */
                            }
                        }
                    }));
                    stage1Log("sub3-hooked-deferred",
                        destination.toString());
                } catch (err) {
                    stage1Log("candidate-hook-failed", String(err));
                }
            }, 0);
        }
    }
}

/* Parse forward from `fromAddress`, collecting the destinations of direct
 * (E8) calls -- the PIN original takes the next executed call; scanning and
 * then fingerprinting the arguments is both cheaper and less fragile. */
function stage1ScanCalls(fromAddress, stopAtRet) {
    const destinations = [];
    let address = fromAddress;
    let parsed = 0;
    let firstMnemonic = null;
    let parseError = null;

    /* Follow a jump thunk first.
     *
     * Round 78 answered why this scan kept coming back empty: the candidate address
     * starts with a `jmp` (first=jmp, parsed=111, then an invalid instruction). It is
     * a thunk, which is what WinLicense's obfuscation produces all over the unpacked
     * code. Scanning forward from a thunk walks through it into whatever follows and
     * finds no calls at all, so a function that really is rsa_exptmod gets rejected.
     *
     * A thunk's whole purpose is to be followed: resolve the jump and scan the target. */
    try {
        const first = Instruction.parse(address);

        if (first.mnemonic === "jmp") {
            const opcode = Memory.readU8(address);
            let target = null;

            if (opcode === 0xE9) {
                // jmp rel32
                target = address.add(5).add(Memory.readS32(address.add(1)));
            } else if (opcode === 0xFF && Memory.readU8(address.add(1)) === 0x25) {
                // jmp qword ptr [rip + disp32]
                const disp = Memory.readS32(address.add(2));
                const slot = address.add(6).add(disp);
                target = slot.readPointer();
            }

            if (target !== null && !target.isNull()) {
                stage1Log("sub2-thunk-followed", "candidate " + fromAddress +
                    " is a jmp thunk -> " + target);
                address = target;
            }
        }
    } catch (e) {
        /* Not a thunk, or unreadable; scan from the candidate itself. */
    }

    for (let i = 0; i < 4000; i++) {
        let insn;
        try {
            insn = Instruction.parse(address);
        } catch (e) {
            /* Record why the scan stopped.
             *
             * "no direct calls" has two very different causes: the function really
             * has none, or the first instruction could not be parsed at all (an
             * unreadable or unmapped region). Both produce an empty list, and the
             * fix is different for each -- so keep the count and the first error. */
            parseError = String(e);
            break;
        }
        parsed++;
        if (firstMnemonic === null) {
            firstMnemonic = insn.mnemonic;
        }
        /* Stopping at the first ret is right when scanning a whole function from
         * its entry, and wrong here: the validation below starts at a candidate's
         * *return* address, which usually lands part-way into rsa_exptmod, so the
         * scan hits a ret belonging to an inner block long before it reaches the
         * mp_exptmod call. Round 60 rejected 400+ candidates for exactly this
         * reason ("no direct calls -- not rsa_exptmod"). The real filter is the
         * arguments of each call (looksLikeKeyMpInt), so extra destinations from
         * scanning on are harmless; pass stopAtRet=false to keep going. */
        if ((stopAtRet !== false) &&
            (insn.mnemonic === "ret" || insn.mnemonic === "retf")) {
            break;
        }
        if (insn.mnemonic === "call") {
            try {
                if (Memory.readU8(address) === 0xE8) {
                    const rel = Memory.readS32(address.add(1));
                    destinations.push(address.add(5 + rel));
                }
            } catch (e) {
                /* indirect or unreadable */
            }
        }
        address = insn.next;
    }
    stage1ScanCalls.lastParsed = parsed;
    stage1ScanCalls.lastFirst = firstMnemonic;
    stage1ScanCalls.lastError = parseError;
    return destinations;
}

/* Does this pointer look like a libtommath mp_int whose digit count matches
 * one of the RSA key components we are about to swap in? */
function looksLikeKeyMpInt(pointer) {
    if (pointer.isNull()) {
        return null;
    }
    const keys = plan.rsaKeys;
    if (keys === null) {
        return null;
    }
    const expected = [keys.mod1Len, keys.exp1Len, keys.mod2Len, keys.exp2Len];
    try {
        const used = pointer.readS32();
        const alloc = pointer.readS32();
        const sign = pointer.readS32();
        const dp = pointer.add(mpIntDpOffset()).readPointer();
        if (used <= 0 || alloc < used || sign < 0 || sign > 1 ||
            dp.isNull()) {
            return null;
        }
        if (expected.indexOf(used) < 0) {
            return null;
        }
        /* the digits must be readable */
        dp.add((used - 1) * 4).readU32();
        return { used: used, alloc: alloc, sign: sign, dp: dp };
    } catch (e) {
        return null;
    }
}

/* Called at the entry of every direct call inside rsa_exptmod: the RSA call
 * is the one whose arguments are the key mp_ints. */
/* The PIN mechanism, ported. wl-extract's Stage 1 does not guess a return
 * address: process_ins waits for the next direct call executed after the
 * license read and takes its destination as mp_exptmod. Everything the swap
 * needs is in that call's arguments, so nothing has to be hooked out of band
 * and the callout that caught the call performs the swap itself.
 *
 * Only the memory accesses and the log happen here; anything that calls into
 * the agent (Interceptor, guard re-protection, Stage 2) is deferred, because a
 * Frida API called from inside a Stalker callout deadlocks the target thread. */
function stage1CallWatch(context, site) {
    const stage1 = plan.stage1;
    stage1.callWatchTries = (stage1.callWatchTries || 0) + 1;

    const keys = stage1KeyMaterial();
    const slots = plan.stage1KeySlots;
    const described = [];
    let matches = 0;
    let heapMatches = 0;
    let ours = 0;
    for (let i = 0; i < slots.length; i++) {
        const value = slotRead(context, slots[i]);
        const shape = looksLikeKeyMpInt(value);
        described.push("arg" + i + "=" + value + " " +
            (shape === null ? describeMpInt(value) : "MP_INT" +
                JSON.stringify(shape.used)));
        if (shape !== null) {
            matches++;
            /* mp_exptmod's operands are heap mp_ints. x86 VPIplayer matched
             * [esp+8] holding a stack address left behind by the license read's
             * own frame, and that false positive consumed the one identification
             * attempt (sub4-found-mp_exptmod 0x6bed17 with arg1=null, then a
             * single swap and no further calls). */
            if (!stage1IsStackValue(value, context)) {
                heapMatches++;
            }
        }
        if (keys !== null &&
            (value.equals(keys.key1.exp.struct) ||
             value.equals(keys.key1.mod.struct) ||
             value.equals(keys.key2.exp.struct) ||
             value.equals(keys.key2.mod.struct))) {
            ours++;
        }
    }
    stage1Log("call-watch", "try#" + stage1.callWatchTries + " " +
        site.address + " -> " + site.dest + " matches=" + matches +
        " heap=" + heapMatches + " ours=" + ours +
        " spd=" + (stage1.landmarkSp === null
            ? "-" : context[SP_REG].sub(stage1.landmarkSp).toString()) +
        " " + described.join(" | "));
    /* Two heap-resident mp_ints: mp_exptmod takes four arguments and its
     * second and third are the base and the exponent. */
    if (heapMatches < 2 && ours === 0) {
        return;
    }

    if (!stage1.mpExptmod) {
        stage1.mpExptmod = site.dest.toString();
        stage1.sub = 5;
        stage1.path = "call";
        for (const slot of plan.decLicArgSlots) {
            const value = slotRead(context, slot);
            if (!value.isNull()) {
                stage1.decLic = value.toString();
                report.stage1DecLic = stage1.decLic;
                stage1Log("dec-lic-from-arg", "call-watch destination " +
                    stage1.decLic + " (frame value was " +
                    report.stage1DecLic + ")");
                break;
            }
        }
        stage1Log("sub4-found-mp_exptmod", "call-watch " + site.dest +
            " matched " + matches + " key-shaped args: " +
            described.join(" | "));
    }

    stage1.callCount++;
    if (stage1.callCount < stage1CallThreshold(stage1)) {
        if (keys !== null) {
            slotWrite(context, slots[0], keys.key2.exp.struct);
            slotWrite(context, slots[1], keys.key2.mod.struct);
        }
        stage1Log("swap", "call#" + stage1.callCount + " <- rsa_key_2");
        return;
    }
    if (keys !== null) {
        const finalKey = stage1FinalKey(keys);
        slotWrite(context, slots[0], finalKey.exp.struct);
        slotWrite(context, slots[1], finalKey.mod.struct);
    }
    stage1Log("swap", "call#" + stage1.callCount + " <- " +
        (plan.stage1CompleteAfter > 0 ? "rsa_key_2" : "rsa_key_1"));
    stage1.sub = 6;
    report.stage1DecLic = stage1.decLic;
    report.stage1Complete = true;
    stage1Log("complete", "dec_lic=" + stage1.decLic +
        " (RSA-decrypted license buffer, Stage 2 input)");
    const decLic = stage1.decLic;
    setTimeout(function () {
        try {
            disarmGuard();
            if (decLic !== null && decLic !== undefined) {
                startStage2(decLic);
                /* This tick already runs after the call returned, so the
                 * output mp_int may be populated; refresh either way. */
                stage2RefreshBuffer();
            }
        } catch (e) {
            stage1Log("call-watch-complete-error", String(e));
        }
    }, 0);
}

function stage1CallCandidate(context, destination) {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub < 3 || stage1.sub === 6) {
        return;
    }
    /* A hooked return address was actually reached, so this path owns Stage 1;
     * the call watcher stands down to avoid counting the same calls twice. */
    stage1.path = "ret";
    const slots = plan.stage1KeySlots;
    const described = [];
    let matches = 0;
    let ours = 0;
    const keyMaterial = stage1KeyMaterial();
    const values = [];
    for (let i = 0; i < slots.length; i++) {
        const value = slotRead(context, slots[i]);
        values.push(value);
        const shape = looksLikeKeyMpInt(value);
        described.push("arg" + i + "=" + value + " " +
            (shape === null ? describeMpInt(value) : "MP_INT" +
                JSON.stringify(shape.used)));
        if (shape !== null) {
            matches++;
        }
        if (keyMaterial !== null &&
            (value.equals(keyMaterial.key1.exp.struct) ||
             value.equals(keyMaterial.key1.mod.struct) ||
             value.equals(keyMaterial.key2.exp.struct) ||
             value.equals(keyMaterial.key2.mod.struct))) {
            ours++;
        }
    }
    /* A call whose arguments are already our own key structs is a *subsequent*
     * mp_exptmod call, not a non-match. The protection reuses the same argument
     * slots, so after the first swap they hold the struct we wrote -- whose
     * `used` is 0, which looksLikeKeyMpInt rejects. Returning here on
     * matches === 0 stopped the call count at 1 (ngahost#7: "matched 1
     * key-shaped args", then every later call logged sub4-no-key-match and was
     * never counted), and the completion branch (callCount > decSections) could
     * never fire. */
    if (matches === 0 && ours === 0) {
        /* Say why nothing matched instead of returning silently: with no log
         * this looked exactly like "the hook never fired" (callCount stayed
         * 0), which sent two runs chasing the wrong thing. */
        stage1.noMatchCalls = (stage1.noMatchCalls || 0) + 1;
        if (stage1.noMatchCalls <= 3) {
            stage1Log("sub4-no-key-match", "target " + destination +
                " rsaKeys=" + (plan.rsaKeys === null ? "null" : "set") +
                " matches=" + matches + " ours=" + ours +
                " args: " + described.join(" | "));
        }
        return;
    }
    stage1.callCount++;
    /* Log the raw arguments of the first few calls BEFORE the swap, and
     * whether each one is already one of our own mp_int structs. What
     * distinguishes the protection's verify call from its decrypt calls is
     * the only thing that can make completion robust when the number of calls
     * does not match the dec_sections model (observed calls=2 against
     * dec_sections=3, so `callCount > decSections` never fires). */
    if (stage1.callCount <= 3) {
        const rawKeys = stage1KeyMaterial();
        const raw = [];
        for (let i = 0; i < slots.length; i++) {
            const value = slotRead(context, slots[i]);
            let ours = "-";
            if (rawKeys !== null) {
                ours = (value.equals(rawKeys.key1.exp.struct) ||
                        value.equals(rawKeys.key1.mod.struct)) ? "key1"
                    : ((value.equals(rawKeys.key2.exp.struct) ||
                        value.equals(rawKeys.key2.mod.struct)) ? "key2"
                       : "foreign");
            }
            raw.push("arg" + i + "=" + value + "(" + ours + ")");
        }
        stage1Log("sub4-call-raw", "call#" + stage1.callCount + " " +
            raw.join(" ") + " | " + described.join(" | "));
    }
    if (stage1.callCount === 1) {
        stage1.mpExptmod = destination.toString();
        stage1.sub = 5;
        stage1Log("sub4-found-mp_exptmod", "call target " + destination +
            " matched " + matches + " key-shaped args: " +
            described.join(" | "));
        /* dec_lic is mp_exptmod's output buffer, i.e. its 4th argument. Read
         * it from there: the PIN original's [esp+0x8c] frame offset is
         * x86-only and never matched on x64. */
        let choseDecLic = false;
        for (const slot of plan.decLicArgSlots) {
            const value = slotRead(context, slot);
            if (!value.isNull()) {
                const fromFrame = report.stage1DecLic;
                stage1.decLic = value.toString();
                report.stage1DecLic = stage1.decLic;
                stage1Log("dec-lic-from-arg", "mp_exptmod destination " +
                    stage1.decLic + " (frame value was " + fromFrame + ")");
                choseDecLic = true;
                break;
            }
        }
        if (!choseDecLic) {
            /* Two of round 25's three completions ended with dec_lic=null and
             * were handed to Stage 2 as "skipped", with nothing saying why.
             * Show what the slots actually held. */
            stage1Log("dec-lic-none", "arg slots: " +
                plan.decLicArgSlots.map(function (slot) {
                    return slotRead(context, slot).toString();
                }).join(" ") + " frame candidates: " +
                plan.decLicCandidates.map(function (offset) {
                    let value = "unreadable";
                    try {
                        value = context[SP_REG].add(offset).readPointer()
                            .toString();
                    } catch (e) {
                        /* leave the marker */
                    }
                    return "[sp+" + offset.toString(16) + "]=" + value;
                }).join(" "));
        }
    } else {
        stage1Log("rsa-call-again", "call#" + stage1.callCount + " at " +
            destination + " " + described.join(" | "));
    }
    const keys = stage1KeyMaterial();
    if (keys === null) {
        return;
    }
    if (stage1.callCount < stage1CallThreshold(stage1)) {
        slotWrite(context, slots[0], keys.key2.exp.struct);
        slotWrite(context, slots[1], keys.key2.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- rsa_key_2");
    } else {
        const finalKey = stage1FinalKey(keys);
        slotWrite(context, slots[0], finalKey.exp.struct);
        slotWrite(context, slots[1], finalKey.mod.struct);
        stage1Log("swap", "call#" + stage1.callCount + " <- " +
            (plan.stage1CompleteAfter > 0 ? "rsa_key_2" : "rsa_key_1"));
        disarmGuard();
        stage1.sub = 6;
        report.stage1DecLic = stage1.decLic;
        report.stage1Complete = true;
        stage1Log("complete", "dec_lic=" + stage1.decLic +
            " (RSA-decrypted license buffer, Stage 2 input)");
        /* Hand the decrypted buffer to Stage 2, which keys on the 2-byte
         * read of dec_lic + 0x33 (stage2.cpp's stage2::init). */
        if (stage1.decLic !== null && stage1.decLic !== undefined) {
            stage1Log("stage2-handoff", "decLic=" + stage1.decLic);
            try {
                startStage2(stage1.decLic);
                stage1Log("stage2-armed", "sub=" + plan.stage2.sub);
                /* The output mp_int is still empty at this point (we are inside
                 * the call's onEnter); re-resolve its digit buffer once the RSA
                 * write has happened. See stage2RefreshBuffer. */
                setTimeout(stage2RefreshBuffer, 20);
                /* Locate the decrypted buffer by its contents: the
                 * argument-derived addresses have been ruled out (rounds
                 * 31/33). Runs on the JS thread -- scanning memory inside the
                 * hook would stall it. */
                setTimeout(stage2LocateBufferByContent, 25);
            } catch (e) {
                stage1Log("stage2-start-failed", String(e));
            }
        } else {
            stage1Log("stage2-skipped", "decLic=" + stage1.decLic);
        }
    }
}

/* Candidate "return address back in rsa_exptmod" slots. The PIN original
 * hardcodes [esp+8]; on x64 the frame layout differs, so several slots are
 * collected and the first one that holds a non-system address is used (and
 * reported, so the offsets can be pinned down). */
/* How many RSA calls to let through before Stage 1 is done, and which key to
 * install on that last call.
 *
 * The mimic (and whatlicense's model) expects dec_sections + 1 calls, the last
 * one restoring the real key. A real sample calls the routine *once*: it
 * decrypts the first section with the swapped key, gets a blob it does not
 * like, and gives up -- so "callCount > decSections" never fires and Stage 1
 * never completes (ngahost#9: sub4-found-mp_exptmod, swap call#1, and no
 * call#2). STAGE1_COMPLETE_AFTER=1 ends Stage 1 on that first call, with our
 * key still in place, so Stage 2 gets to run. */
function stage1CallThreshold(stage1) {
    return plan.stage1CompleteAfter > 0
        ? plan.stage1CompleteAfter
        : (stage1.decSections + 1);
}

/* On the final call the original flow restores the real key so the
 * protection's own decryption of the last section stands. In single-call mode
 * there is no earlier section, so our key stays and the decrypted content is
 * deterministic. */
function stage1FinalKey(keys) {
    return plan.stage1CompleteAfter > 0 ? keys.key2 : keys.key1;
}

/* Is this value a pointer into the current stack frame's neighbourhood?
 * mp_exptmod's operands are heap mp_ints, never stack addresses, so this
 * separates a real argument from a stale slot the license read left behind. */
function stage1IsStackValue(value, context) {
    try {
        const sp = context[SP_REG];
        return value.compare(sp) >= 0 && value.compare(sp.add(0x40000)) < 0;
    } catch (e) {
        return false;
    }
}

/* True for Windows' own DLLs. The protection's code lives either in the main
 * module's image or in memory it allocated for itself (findModuleByAddress
 * returns null for the latter); neither is a system module. Filtering on the
 * module *path* rather than on the main module's name keeps both. */
function stage1IsSystemModule(module) {
    if (module === null || module === undefined) {
        return false;
    }
    const path = (module.path || "").toLowerCase();
    return path.indexOf("\\windows\\") !== -1;
}

/* True when the address is backed by executable memory. Interceptor.attach
 * rewrites the bytes at the target address, so attaching to a data address
 * (a stack slot holding a buffer pointer, say) corrupts that buffer -- which
 * is exactly what crashed the x86 mimic run with an access violation after
 * it "hooked" the license copy itself. */
function stage1IsExecutable(address) {
    if (address === null || address === undefined || address.isNull()) {
        return false;
    }
    try {
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf("x") !== -1;
    } catch (e) {
        return false;
    }
}

function stage1RankCandidates(snapshot) {
    const slots = [];
    const pc = snapshot.pc;
    /* Rank by "same memory range as the code that did the read": the caller
     * (rsa_exptmod) lives in the same private allocation as
     * mp_read_unsigned_bin, so a stack slot pointing into that range is the
     * return address we want.
     *
     * Thread.backtrace is deliberately NOT used. Calling it from inside the
     * exception handler killed the target outright (run 38042084163), and the
     * old [sp+0..0x28] scan was too narrow -- mp_read_unsigned_bin's frame is
     * bigger, and on the x64 mimic target no candidate came anywhere near the
     * reading pc. */
    let preferred = null;
    try {
        preferred = Process.findRangeByAddress(pc);
    } catch (e) {
        preferred = null;
    }
    for (const slot of snapshot.values) {
        const value = slot.value;
        const module = Process.findModuleByAddress(value);
        const executable = stage1IsExecutable(value);
        let sameRange = false;
        if (preferred !== null && executable) {
            try {
                const range = Process.findRangeByAddress(value);
                sameRange = range !== null &&
                    range.base.equals(preferred.base);
            } catch (e) {
                sameRange = false;
            }
        }
        slots.push({
            offset: slot.offset,
            label: "sp+" + slot.offset.toString(16),
            value: value.toString(),
            inModule: !stage1IsSystemModule(module) && executable,
            sameRange: sameRange
        });
    }
    /* Keep the counts.
     *
     * Round 79 showed sub1-no-code-return-candidate firing 52 times against 57
     * landmarks: roughly nine landmarks in ten yield no usable candidate, so the frame
     * scan is the bottleneck, not the scan-for-calls that follows it. Whether it finds
     * nothing or finds things it then filters is the difference between scanning
     * deeper and fixing the filter, so record both numbers. */
    let executable = 0;
    let nonSystem = 0;
    for (const slot of slots) {
        if (slot.value !== "0x0") {
            if (slot.sameRange) {
                nonSystem++;
            }
        }
    }
    for (const slot of slots) {
        try {
            if (stage1IsExecutable(ptr(slot.value))) {
                executable++;
            }
        } catch (e) {
            /* unreadable */
        }
    }
    stage1RankCandidates.lastStats = {
        slots: slots.length,
        executable: executable,
        usable: slots.filter(function (s) { return s.inModule; }).length,
        sameRange: nonSystem
    };
    /* Same-range candidates first: they are the plausible callers. */
    slots.sort(function (a, b) {
        return (b.sameRange ? 1 : 0) - (a.sameRange ? 1 : 0);
    });
    return slots;
}

function stage1CandidateLabel(candidate) {
    return candidate.label !== undefined
        ? candidate.label
        : "sp+" + candidate.offset.toString(16);
}

/* ---------------------------------------------------------------------
 * Guard-page plumbing.
 *
 * The PIN original sees every read through INS callouts. Frida's closest
 * equivalent for "tell me when this page is touched" is a real Windows
 * guard page: PAGE_READWRITE | PAGE_GUARD raises a one-shot
 * STATUS_GUARD_PAGE_VIOLATION (0x80000001) on the first access and the OS
 * then clears the guard bit, so the instruction simply retries. That is
 * *not* the same as Memory.protect(..., "---"): a no-access page raises a
 * hard ACCESS_VIOLATION (0xC0000005), which the target's own SEH treats as
 * a crash. The license copy lives on the heap, so the allocator or the
 * program writing anywhere else in that page would kill the process --
 * which is exactly the 2.7s exit this replaces.
 *
 * The guard is armed once and never re-armed: the OS clears the guard bit on
 * the first violation so the faulting instruction retries and completes. Re-
 * arming inside the handler would make that retry fault again on the same
 * instruction and spin the thread forever (observed as the status RPC timing
 * out while the process stayed alive). The first read anywhere in the page is
 * taken as the landmark instead.
 * ------------------------------------------------------------------- */
const PAGE_READWRITE = 0x04;
const PAGE_GUARD = 0x100;

/* Cap on deferred re-arms. A page that is touched continuously would
 * otherwise re-arm forever; after this many attempts we give up and say so
 * rather than slowing the target to a crawl. */
const MAX_REARMS = 20000;

let virtualProtect = null;
function getVirtualProtect() {
    if (virtualProtect === null) {
        const addr = Module.getExportByName("kernel32.dll",
            "VirtualProtect");
        virtualProtect = new NativeFunction(addr, "int",
            ["pointer", "size_t", "uint32", "pointer"]);
    }
    return virtualProtect;
}

/* Re-arm the guard AFTER the faulting instruction has retried and completed.
 *
 * Arming from inside the exception handler is fatal: the OS clears the guard
 * bit when it raises STATUS_GUARD_PAGE_VIOLATION so the faulting instruction
 * can retry, and putting the guard back before that retry makes the retry
 * fault on the same instruction again -- the thread then spins inside the
 * handler forever (observed as the status RPC timing out while the process
 * stayed alive). Deferring to the JS thread lets the retry finish first.
 */
function scheduleRearm() {
    const stage1 = plan.stage1;
    if (!stage1.active || stage1.sub !== 1 || stage1.rearmPending) {
        return;
    }
    if (stage1.rearms >= MAX_REARMS) {
        if (!stage1.rearmCapped) {
            stage1.rearmCapped = true;
            stage1Log("rearm-capped", "gave up after " + stage1.rearms +
                " re-arms; the page is touched continuously");
        }
        return;
    }
    stage1.rearmPending = true;
    setTimeout(function () {
        stage1.rearmPending = false;
        if (plan.stage1.active && plan.stage1.sub === 1) {
            plan.stage1.rearms++;
            armGuard();
        }
    }, 0);
}

function armGuard() {
    const stage1 = plan.stage1;
    if (stage1.guardStart === null || stage1.guardLength <= 0) {
        stage1.guardArmed = false;
        return false;
    }
    const old = Memory.alloc(4);
    const ok = getVirtualProtect()(stage1.guardStart,
        stage1.guardLength, PAGE_READWRITE | PAGE_GUARD, old);
    stage1.guardArmed = ok !== 0;
    return stage1.guardArmed;
}

function disarmGuard() {
    const stage1 = plan.stage1;
    if (stage1.guardStart === null || stage1.guardLength <= 0) {
        return;
    }
    const old = Memory.alloc(4);
    getVirtualProtect()(stage1.guardStart, stage1.guardLength,
        PAGE_READWRITE, old);
    stage1.guardArmed = false;
}

/* Trace for a bounded stretch, starting from the licence read.
 *
 * The transform is what makes Stage 1's landmark findable, and it is also what
 * makes the protection give up (round 51: licence reads 52 with it off, 0 with it
 * on). Tracing only around the licence code gets both. */
function stage1OpenWindow() {
    let followed = 0;
    for (const thread of Process.enumerateThreads()) {
        try {
            Stalker.follow(thread.id, { transform: install });
            followed++;
        } catch (e) {
            /* best effort */
        }
    }
    emit({ spike: "stage1", event: "window-open", threads: followed,
           detail: "bounded tracing from the licence read" });
    /* Two seconds, not six.
     *
     * Round 65 measured what the window costs: across 21 attempts the protection
     * read the licence page exactly once (guard-hit 1), so six seconds of slowdown
     * per attempt was suppressing the very event everything downstream depends on.
     * The RSA call appeared 1.8-2.5s in when tracing ran from map time, so two
     * seconds still covers it while leaving the target alone for the rest. */
    setTimeout(function () {
        /* No extension.
         *
         * Round 57 tried holding the window open in six-second steps while Stage 1
         * was pending, and it made things worse in exactly the way round 51
         * described: window-extend 56, and the protection's licence reads fell from
         * 46 to 4. Keeping the target slowed is what stops the protection working,
         * so the window has to close on schedule and let the run continue. The rate
         * of Stage 1 landmarks has to be improved inside a short window, not by
         * making the window long. */
        let stopped = 0;
        for (const thread of Process.enumerateThreads()) {
            try {
                Stalker.unfollow(thread.id);
                stopped++;
            } catch (e) {
                /* best effort */
            }
        }
        try {
            Stalker.flush();
        } catch (e) {
            /* best effort */
        }
        emit({ spike: "stage1", event: "window-close", threads: stopped,
               detail: "bounded window over; target back to full speed" });
    }, 2000);
}

function stage1OnLicensePageAccess(details) {
    const stage1 = plan.stage1;
    if (!stage1.active) {
        return false;
    }
    const memory = details.memory || null;
    let address = null;
    let operation = "read";
    if (memory !== null) {
        address = memory.address;
        operation = memory.operation || "read";
    }
    /* A guard-page violation does not always carry the memory descriptor;
     * the faulting address is still on the exception record. */
    if ((address === null || address === undefined) &&
        details.address !== undefined && details.address !== null) {
        address = details.address;
    }
    if (address === null || address === undefined) {
        return false;
    }
    /* Not our page at all: let the exception go to the target. */
    if (stage1.guardStart === null ||
        address.compare(stage1.guardStart) < 0 ||
        address.compare(stage1.guardStart.add(stage1.guardLength)) >= 0) {
        return false;
    }
    /* In our guard page. Past sub-stage 1 the guard is supposed to have been
     * disarmed; if a stale page still faults (the OS clears the guard bit
     * only on the page that faulted, and the guard spans whole pages), let
     * the access through instead of returning false, which would hand the
     * violation to the target's own SEH and kill the process. */
    if (stage1.sub !== 1) {
        disarmGuard();
        return true;
    }
    /* Guard pages are page-granular, so unrelated objects sharing the page
     * fault too. Count them: a runaway count means the guard strategy needs
     * rethinking. */
    stage1.guardHits = (stage1.guardHits || 0) + 1;
    if (stage1.guardHits <= 8) {
        stage1Log("guard-hit", "#" + stage1.guardHits + " op=" + operation +
            " addr=" + address + " lic_copy=" + stage1.preRsaBuf);
    }
    /* The tracing window is opened when the licence copy is resolved, not here:
     * this hit is the protection reading the licence, which happens after the RSA
     * step that Stage 1 needs to see (round 52 caught nothing here). */
    /* The first READ in the guarded page that comes from the main module is
     * the landmark.
     *
     * Deliberately do NOT re-arm synchronously. The OS cleared the guard bit
     * on this violation, so the faulting instruction retries and completes.
     * Re-arming here would make that retry fault again on the very same
     * instruction and spin the thread forever -- observed as the status RPC
     * timing out while the process stayed alive. Collateral reads are
     * skipped with a deferred re-arm instead (scheduleRearm).
     *
     * Requiring the address to be inside [lic_copy, lic_copy + lic_size) was
     * wrong: that is only the file image, while the program's license
     * structure spans the whole page (the byte-store candidates land at
     * 0x608b80, 0x608bb7 and 0x608d30 for a 465-byte license).
     */
    if (operation !== "read") {
        return true;
    }
    /* The guard bit is already consumed by this violation, so the instruction
     * will retry and succeed. If the exception record carries no context we
     * cannot read the pc; let the access through rather than returning false,
     * which would hand a guard-page violation to the target's own SEH and
     * kill the process. */
    const ctx = details.context || null;
    if (ctx === null) {
        return true;
    }
    const pc = ctx[PC_REG];
    /* Skip only reads issued from a Windows system module. Those are heap
     * bookkeeping on the same page (the previous run showed pc=0x7ffd3ddde6cb
     * in ntdll.dll reading the license page twice). Everything else counts:
     * WinLicense's unpacked protection code does not reliably live inside the
     * main module's image -- it is frequently in memory the protection
     * allocated for itself, which findModuleByAddress reports as null. Gating
     * on the main module discarded exactly the read this stage hunts for. */
    const from = Process.findModuleByAddress(pc);
    if (stage1IsSystemModule(from)) {
        stage1.collateralReads = (stage1.collateralReads || 0) + 1;
        /* The read came through a system library, but its caller is what decides:
         * round 59 had 15 collateral reads all with pc in ntdll and no landmark at
         * all, because the protection reads its licence through the CRT's copy
         * routines. Any frame pointing outside the system modules -- into the main
         * module, or into memory the protection allocated for itself, which
         * findModuleByAddress reports as null -- is the protection's own read. */
        let callerIsProtection = false;
        const frame = [];
        const sp = ctx[SP_REG];
        for (let off = 0; off <= 0x60; off += PTR_SIZE) {
            try {
                const value = sp.add(off).readPointer();
                let tag = "";
                if (!value.isNull()) {
                    const module = Process.findModuleByAddress(value);
                    if (module === null) {
                        tag = " <private>";
                        callerIsProtection = true;
                    } else if (!stage1IsSystemModule(module)) {
                        tag = " " + module.name;
                        callerIsProtection = true;
                    }
                }
                frame.push("[sp+" + off.toString(16) + "]=" + value + tag);
            } catch (e) {
                /* unreadable slot */
            }
        }
        if (stage1.collateralReads <= 5) {
            /* Log the raw stack window and tag every slot that points into a
             * non-system module. The protection may read its license copy
             * through the CRT's memcpy/memmove, which lives in System32 -- the
             * read would then be discarded as "collateral" even though its
             * caller is the protection. The caller's return address is the
             * only thing that distinguishes the two, and Thread.backtrace
             * cannot be used here (it kills the target), so read the slots. */
            stage1Log("sub1-collateral-read", "pc=" + pc + " (" +
                from.name + ") addr=" + address + " frame: " +
                frame.join(" "));
        }
        if (!callerIsProtection) {
            /* Skip it and keep watching: re-arm once the retry has completed. */
            scheduleRearm();
            return true;
        }
        stage1Log("sub1-landmark-via-crt", "pc=" + pc + " (" + from.name +
            ") addr=" + address + " -- caller outside the system modules");
    }
    stage1.landmarks = (stage1.landmarks || 0) + 1;
    /* Count landmarks, not guard hits: the guard page is re-armed after every
     * collateral read, so on a busy run the landmark can be the 9th hit and a
     * `guardHits <= 8` window silently drops the event -- which is how a run
     * that reached sub-stage 5 (real mp_exptmod, two calls) still reported
     * landmark=False. */
    if (stage1.landmarks <= 8) {
        stage1Log("sub1-landmark-module", "pc=" + pc + " in " +
            (from === null ? "<private>" : from.name));
    }
    /* Minimal work inside the exception handler. Reading a window of raw
     * stack slots and the pc is cheap and safe; every range lookup, sort and
     * Interceptor.attach is deferred to the JS thread. Doing the heavy
     * version in the handler is what killed the target in run 38042084163
     * (process gone right after sub1-landmark-module, with no
     * exception-handler-error logged). */
    const snapshot = stage1CaptureLandmark(ctx);
    setTimeout(function () {
        /* Round 58: the target dies right after sub1-landmark-module (rc=1 with no
         * dumps, the same symptom the note above records from run 38042084163), and
         * take-landmark/sub2/call-watch never appear. Log each phase so the next run
         * says which one kills it instead of leaving it to inference. */
        try {
            stage1Log("take-landmark-begin", "pc=" + snapshot.pc);
            stage1TakeLandmark(snapshot, "op=" + operation + " addr=" + address);
            stage1Log("take-landmark-end", "sub=" + stage1.sub);
        } catch (e) {
            stage1Log("take-landmark-error", String(e) +
                (e !== null && e !== undefined && e.stack !== undefined
                    ? " | " + e.stack : ""));
        }
    }, 0);
    return true;
}

/* Capture only what is valid inside the exception handler: the pc and the
 * raw stack window. Returns a plain object, so nothing here depends on the
 * CpuContext staying alive. */
function stage1CaptureLandmark(context) {
    const pc = context[PC_REG];
    const sp = context[SP_REG];
    const values = [];
    const step = Process.pointerSize;
    /* Deeper than it was.
     *
     * The window was 0x400, and round 79 showed the scan coming back empty in roughly
     * nine landmarks out of ten (sub1-no-code-return-candidate 52 against 57
     * landmarks). The guard hit arrives from ntdll -- a CRT copy -- so the
     * protection's own return addresses sit well below that frame. Reading stack slots
     * is cheap and safe even inside the exception handler (unlike range lookups or
     * Interceptor.attach, which are deferred), so widen the window. */
    for (let offset = 0; offset <= 0x1000; offset += step) {
        try {
            values.push({
                offset: offset,
                value: sp.add(offset).readPointer()
            });
        } catch (e) {
            break;
        }
    }
    return { pc: pc, sp: sp, values: values };
}

/* Sub-stage 1 landmark, shared by both landmark mechanisms.
 *
 * The guard page knows the accessed address; a hardware breakpoint does not
 * (Frida exposes no Dr6), but both know the pc and the stack. Everything
 * after the landmark is identical, so it lives here.
 */
function stage1TakeLandmark(snapshot, label) {
    const stage1 = plan.stage1;
    /* Arm the PIN-style call watcher: from here on, the first direct call the
     * thread executes is the RSA call (stage1.cpp::process_ins). This is the
     * path that works when no stack slot holds a usable return address --
     * x86 VPIplayer hooks six candidates and reaches none of them, and x64
     * ngahost#7 has no code address in the frame at all
     * (sub1-no-code-return-candidate). */
    stage1.landmarkSeen = true;
    stage1.landmarkSp = snapshot.sp;
    try {
        stage1.landmarkTid = Process.getCurrentThreadId();
    } catch (e) {
        stage1.landmarkTid = null;
    }
    /* Actually clear PAGE_GUARD here, not just the bookkeeping flag. The guard
     * spans whole pages, and the OS clears the guard bit only on the page
     * that faulted -- with a 4096-byte license the guard covers two pages, so
     * the second one is still armed. Once sub-stage 1 is done the handler
     * returns false for any further violation, which hands it to the target's
     * SEH and kills the process (run 38043143769: a guard-page read at
     * lic_copy + 0x1000 immediately after sub3-call-candidates). */
    disarmGuard();
    const candidates = stage1RankCandidates(snapshot);
    stage1.retCandidates = candidates;
    stage1Log("sub1-lic-page-access", label + " pc=" + snapshot.pc + " " +
        candidates.slice(0, 12).map(function (candidate) {
            return "[" + stage1CandidateLabel(candidate) + "]=" +
                candidate.value + (candidate.inModule ? " (code)" : "") +
                (candidate.sameRange ? " (same-range)" : "");
        }).join(" "));
    /* The guard bit is already cleared by the OS, so the instruction will
     * succeed on retry; no re-protect is needed. */
    stage1.guardArmed = false;
    /* Hook every stack slot that holds a code address inside the module:
     * the first one to be reached is the return into rsa_exptmod, and
     * logging which slot it was pins the offset down for later runs. */
    const usable = candidates.filter(function (candidate) {
        return candidate.inModule;
    }).slice(0, 6);
    if (usable.length === 0) {
        const stats = stage1RankCandidates.lastStats || {};
        stage1Log("sub1-no-code-return-candidate",
            "logged candidates above; slots=" + stats.slots +
            " executable=" + stats.executable +
            " usable=" + stats.usable +
            " sameRange=" + stats.sameRange);
        /* No stack slot held a code address, so there is nothing to hook.
         * Report it rather than re-arming, which would spin the thread. */
        report.stage1NoReturnCandidate = true;
        return true;
    }
    stage1.sub = 2;
    stage1.retCandidatesInModule = usable.map(function (candidate) {
        return stage1CandidateLabel(candidate) + "=" + candidate.value;
    });
    for (const candidate of usable) {
        const address = ptr(candidate.value);
        const slotLabel = stage1CandidateLabel(candidate);
        setTimeout(function () {
            try {
                /* Check the region before attaching.
                 *
                 * Round 80 got 141 candidates hooked but 25 refusals with "unable to
                 * intercept function at 0x1404c7816; please file a bug" -- addresses
                 * inside NgaHost.exe's image, in the region the protection unpacked
                 * for itself. Interceptor needs to place a trampoline, so a page that
                 * is not writable (or not marked executable) makes it give up.
                 * Report what the range looks like, and make it writable+executable
                 * before retrying. */
                const range = Process.findRangeByAddress(address);
                if (range === null) {
                    stage1Log("sub2-hook-range", address + " is not in a mapped range");
                } else if (range.protection.indexOf("x") < 0 ||
                    range.protection.indexOf("w") < 0) {
                    stage1Log("sub2-hook-range", address + " protection=" +
                        range.protection + " -- re-protecting rwx");
                    try {
                        Memory.protect(range.base, range.size, "rwx");
                    } catch (e) {
                        stage1Log("sub2-hook-protect-failed", String(e));
                    }
                }

                plan.hooks.push(Interceptor.attach(address, {
                    onEnter: function () {
                        try {
                            if (plan.stage1.sub !== 2) {
                                return;
                            }
                            plan.stage1.retSlotOffset = slotLabel;
                            plan.stage1.retToRsa = address.toString();
                            stage1BackInRsaExptmod(this.context);
                        } catch (e) {
                            stage1Log("sub2-error", String(e));
                        }
                    }
                }));
                stage1Log("sub2-hooked", "candidate [" + slotLabel +
                    "] = " + address);
            } catch (e) {
                stage1Log("sub2-hook-failed", String(e) + " for " + address);
            }
        }, 0);
    }
    return true;
}

function startStage1(licCopy) {
    const stage1 = plan.stage1;
    stage1.active = true;
    stage1.sub = 1;
    stage1.preRsaBuf = ptr(licCopy);
    stage1.decSections = Math.floor(plan.licSize / 0x80);
    /* Guard the page holding the license copy: the first read of it is
     * sub-stage 1's landmark, and a guard page costs nothing until it is
     * touched. */
    const pageSize = Process.pageSize;
    const start = ptr(licCopy).and(ptr(pageSize - 1).not());
    const span = Math.max(plan.licSize || 0x100, 1);
    const length = Math.ceil((ptr(licCopy).sub(start).toUInt32() + span) /
        pageSize) * pageSize;
    stage1.guardStart = start;
    stage1.guardLength = length;
    try {
        armGuard();
        stage1Log("start", "lic_copy=" + licCopy + " lic_size=" +
            plan.licSize + " dec_sections=" + stage1.decSections +
            " guard=" + start + "+0x" + length.toString(16) +
            " armed=" + stage1.guardArmed);
        /* Open the bounded tracing window here, not at the guard hit.
         *
         * Round 52 opened it when the guard page reported the licence being read
         * and caught no mp_exptmod call at all. That is the wrong end: the guard
         * hit is the protection reading the licence, which it can only do after
         * the RSA step, so the call Stage 1 needs had already happened. The
         * licence copy being resolved and the guard being armed is the earliest
         * point at which we know the protection is about to work on the licence.
         *
         * Under noTrace, do not open it at all.
         *
         * The transform is not what finds the RSA call: the guard page supplies the
         * landmark and its exception context, stage1RankCandidates picks the return
         * addresses out of that stack, and Interceptor.attach -- one trampoline per
         * function, not a callback per instruction -- waits for the call. The
         * transform only makes everything a hundredfold slower, and a slowed target
         * is what the protection reacts to by skipping its licence work (rounds 51
         * and 57). So in the mode that exists to keep the target fast, keep it fast. */
        if (plan.noTrace) {
            stage1Log("window-skipped",
                "noTrace: guard page + Interceptor carry Stage 1; no transform");
        } else if (plan.stage1WindowOpened !== true) {
            plan.stage1WindowOpened = true;
            stage1OpenWindow();
        }
    } catch (e) {
        stage1Log("guard-failed", String(e) + " -- falling back to " +
            "unguarded detection");
    }
    /* Second, independent landmark mechanism: data breakpoints on the byte
     * store candidates. Exact, so it needs no collateral filtering and no
     * re-arming. Both run at once; whichever sees the license first wins and
     * the other is torn down. */
    try {
        const addresses = Object.keys(plan.copySet).map(function (a) {
            return ptr(a);
        });
        hwBreakInstall(plan, addresses);
    } catch (e) {
        stage1Log("hwbreak-install-failed", String(e));
    }
}

/* Resolve Stage 0 by content on a timer.
 *
 * Round 56: only 6 of 30 attempts reached Stage 0, while the content scan itself
 * worked every time it ran (exactly one hit each). The problem is that the scan
 * only runs from inside the UnmapViewOfFile hook, so when that hook misses the
 * protection's mapping -- it races process start, and tracing_started_at_map
 * reported zero threads in some attempts -- the scan never happens at all. Polling
 * makes Stage 0 independent of catching one syscall at the right moment. */
function startStage0FallbackScan() {
    let ticks = 0;
    const timer = setInterval(function () {
        ticks++;
        const s1 = plan.stage1;
        if (s1 === undefined || s1.active === true || ticks > 20) {
            clearInterval(timer);
            return;
        }
        let hits = [];
        try {
            hits = scanForHead();
        } catch (e) {
            return;
        }
        if (hits.length > 0) {
            clearInterval(timer);
            emit({ spike: "stage0-fallback", event: "content-hit",
                   addr: hits[0], ticks: ticks });
            try {
                startStage1(ptr(hits[0]));
            } catch (e) {
                emit({ spike: "stage0-fallback", event: "error",
                       detail: String(e) });
            }
        }
    }, 250);
}

rpc.exports = {
    setup: function (options) {
        const headBytes = [];
        for (let i = 0; i < HEAD_LEN; i++) {
            headBytes.push(parseInt(options.headHex.substr(i * 2, 2), 16));
        }
        plan = {
            head: headBytes,
            ntPath: options.ntPath || "",
            licSize: options.licSize || 0,
            /* RSA public keys from the wl-lic output (regkey.rsa), as hex
             * digit arrays -- Stage 1 swaps the program's embedded key
             * pointers for these so our license verifies. */
            rsaKeys: options.rsaKeys || null,
            stage1: {
                active: false, sub: 0,
                preRsaBuf: null, retToRsa: null, decLic: null,
                keyRef: null, keyRefReads: 0, guardStart: null,
                guardLength: 0, guardArmed: false, guardHits: 0,
                collateralReads: 0, rearms: 0, rearmPending: false,
                rearmCapped: false,
                retCandidates: [],
                mpExptmod: null, callCount: 0, decSections: 0,
                mpInts: null, firstSwapLogged: false, lastCall: null,
                landmarkSeen: false, landmarkTid: null, callWatchTries: 0,
                landmarkSp: null, path: null
            },
            licMapped: false,
            licCopy: null,
            copySet: {},
            mainThread: null,
            moduleBase: null,
            moduleEnd: null,
            hooks: [],
            followed: [],
            tracing: false,
            exceptionsSeen: 0,
            /* Hardware-breakpoint landmark (spikes/hwbreak_agent.js). Both
             * mechanisms run at once: whichever sees the license first takes
             * sub-stage 1, and the other is torn down. */
            emit: emit,
            PC_REG: PC_REG,
            hwBreakActive: false,
            hwBreakThreads: [],
            hwBreakHits: 0,
            onHwBreakLandmark: function (context) {
                if (plan.stage1.sub !== 1) {
                    return;
                }
                disarmGuard();
                stage1TakeLandmark(stage1CaptureLandmark(context), "hwbreak");
            },
            /* x86 reads the RSA arguments off the stack; x64 keeps them in
             * registers (mp_exptmod(G, X, P, Y): X = exponent, P = modulus,
             * i.e. the 2nd and 3rd arguments). */
            retSlot: IS_IA32 ? { kind: "stack", offset: 0x8 }
                : { kind: "reg", name: "r8" },
            decLicSlot: { kind: "stack", offset: 0x8c },
            decLicCandidates: [0x8c, 0x90, 0x94, 0xa0, 0xb0],
            /* dec_lic read from mp_exptmod's 4th argument (the output
             * buffer) rather than from a frame offset inside rsa_exptmod.
             * The PIN original hardcodes [esp+0x8c], which is x86-only: the
             * x64 frame is laid out differently and no candidate offset ever
             * matched there (decLic stayed null). The destination is the
             * same value either way, and as an argument its location is
             * defined by the ABI instead of by the compiler's frame. */
            decLicArgSlots: IS_IA32
                ? [{ kind: "stack", offset: 0x10 }]
                : [{ kind: "reg", name: "r9" }],
            keyRefOffset: 0x1c,
            stage1KeySlots: IS_IA32
                ? [{ kind: "stack", offset: 0x8 },
                   { kind: "stack", offset: 0xc }]
                : [{ kind: "reg", name: "rdx" },
                   { kind: "reg", name: "r8" }]
        };
        report = {
            platform: Process.platform,
            arch: Process.arch,
            pointerSize: PTR_SIZE,
            errors: [],
            licenseFile: options.licenseFile || "",
            openedPaths: []
        };
        stats = {
            instructions: 0, inside: 0, outside: 0, byteStoresPlanned: 0,
            byteStoresSystem: 0, byteWrites: 0, candidates: 0, maps: 0,
            fileOpens: 0, rwNoMap: 0, rwNoTid: 0, rwNoByte: 0,
            rwByteMismatch: 0, byteWritesFromMem: 0, redirects: 0,
            elapsedMs: 0, readCalloutsPlanned: 0,
            callCalloutsPlanned: 0, insCalloutsPlanned: 0,
            instrumentationErrors: 0, readCalloutsFired: 0
        };

        const modules = Process.enumerateModules();
        const main = modules[0];
        plan.moduleBase = main.base;
        plan.moduleEnd = main.base.add(main.size);
        report.mainModule = main.name + " " + main.base;

        /* The gate everywhere is "not a system module", NOT "the main
         * module". Unpacked protection code usually runs in a private
         * allocation (findModuleByAddress -> null) or in a DLL next to the
         * target, and requiring the main module silently discarded exactly
         * the instructions being hunted: Stage 1's landmark (already fixed)
         * and Stage 0's license-copy byte stores (VPIplayer.exe: 0
         * candidates from 85k byte stores). */
        plan.systemRanges = [];
        for (const module of modules) {
            if (isSystemModule(module)) {
                plan.systemRanges.push([module.base,
                                        module.base.add(module.size)]);
            }
        }
        report.systemModules = plan.systemRanges.length;
        /* Materialise plan.stage2 before any block is compiled: Stalker's
         * transform is compile-time, so a block built before Stage 2 exists
         * can never carry its callout. */
        stage2State();
        if (options.deferTracing) {
            plan.deferTracing = true;
        }
        /* Diagnostic: no map-time transform at all.
         *
         * Rounds 27-32 saw the protection read the licence page 30-50 times per
         * run; from round 33 on it read it zero times while the target stayed
         * alive to the OEP timeout. A per-instruction transform slows the target
         * a hundredfold, which is what an anti-tamper timing check reacts to.
         * This flag separates that from a change in our own code. */
        if (options.noTrace) {
            plan.noTrace = true;
        }

        if (IS_WINDOWS) {
            installWindowsHooks();
            installDiagnosticHooks();
        } else {
            installLinuxHooks();
        }

        /* Only system modules run natively. Everything else -- the main
         * image and the protector's own allocations alike -- has to be
         * traced, or install() never sees its instructions. */
        let excluded = 0;
        for (const module of modules) {
            if (!isSystemModule(module)) {
                continue;
            }
            try {
                Stalker.exclude({ base: module.base, size: module.size });
                excluded++;
            } catch (e) {
                report.errors.push("exclude " + module.name + ": " +
                    String(e));
            }
        }
        report.excludedModules = excluded;

        report.followedThreads = plan.followed;
        if (options.retSlot) { plan.retSlot = options.retSlot; }
        if (options.decLicSlot) { plan.decLicSlot = options.decLicSlot; }
        if (options.keyRefOffset !== undefined) {
            plan.keyRefOffset = options.keyRefOffset;
        }
        if (options.stage1KeySlots) {
            plan.stage1KeySlots = options.stage1KeySlots;
        }
        if (options.retCandidates) {
            plan.retCandidates = options.retCandidates;
        }
        if (options.decLicCandidates) {
            plan.decLicCandidates = options.decLicCandidates;
        }
        /* Candidate stack slots for the return address back into
         * rsa_exptmod: the PIN original uses [esp+8]. */
        plan.retCandidates = options.retCandidates ||
            (IS_IA32 ? [0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18]
                     : [0x0, 0x8, 0x10, 0x18, 0x20, 0x28]);
        /* PIN's Stage 1 mechanism, ported: the next direct call executed after
         * the license read is the RSA call, so no return address has to be
         * guessed. On by default; `callWatch: false` turns it off. */
        plan.callWatch = options.callWatch !== false;
        /* 0 = whatlicense's model (dec_sections + 1 calls, last one restoring
         * the real key); N > 0 = end Stage 1 on the Nth call. A real sample
         * calls the RSA routine once and then gives up, so the model's count is
         * never reached. */
        plan.stage1CompleteAfter = options.stage1CompleteAfter || 0;
        /* Swap in an exponent of 1 so the protection's RSA decrypt becomes the
         * identity and the decrypted buffer is the licence file verbatim. See
         * buildMpIntOne. */
        plan.identityKey = options.identityKey === true;
        /* How far to widen Stage 2's guard ranges. Default 64KB; a diagnostic
         * run widens it to locate the buffer the protection actually reads. */
        plan.guardSpan = options.guardSpan || 0x10000;
        plan.mainModuleName = main.name;
        Process.setExceptionHandler(function (details) {
            try {
                /* Log the first few exceptions so a guard-page violation
                 * (0x80000001) is distinguishable from a genuine crash
                 * (0xC0000005) in the run report. */
                if (plan.exceptionsSeen < 6) {
                    plan.exceptionsSeen++;
                    stage1Log("exception", "type=" + details.type +
                        " addr=" + details.address + " mem=" +
                        (details.memory
                            ? (details.memory.operation + "@" +
                               details.memory.address)
                            : "none"));
                }
                if (hwBreakOnException(plan, details)) {
                    return true;
                }
                if (stage2OnGuardAccess(details)) {
                    return true;
                }
                return stage1OnLicensePageAccess(details);
            } catch (e) {
                stage1Log("exception-handler-error", String(e));
                return false;
            }
        });
        log("stage0 hooks armed (license head " + options.headHex + ")");
        return report;
    },

    /* Stalker has to start AFTER the process is resumed: following a thread
     * that the spawner has stopped does not take effect (the run then traces
     * nothing at all while the hooks still work). The map hook calls this too
     * so tracing cannot be missed even if the host's call is late. */
    startTracing: function () {
        if (plan.tracing) {
            return { alreadyStarted: true, threads: plan.followed.length };
        }
        if (plan.deferTracing) {
            /* Stalker costs ~100x; the protection's own unpacking therefore
             * crawls while it is on. Deferring the follow until the license is
             * mapped lets the unpacking run at native speed and engages the
             * trace exactly where Stage 0 needs it. The MapViewOfFile hook
             * starts it. */
            startStage0FallbackScan();
            return { deferred: true, threads: 0 };
        }
        plan.tracing = true;
        followStart = Date.now();
        /* Materialise plan.stage2 before any block is compiled, so every
         * block carries the Stage 2 callout from the start. */
        stage2State();
        for (const thread of Process.enumerateThreads()) {
            try {
                Stalker.follow(thread.id, { transform: install });
                plan.followed.push(thread.id);
            } catch (e) {
                report.errors.push("follow " + thread.id + ": " + String(e));
            }
        }
        report.followedThreads = plan.followed;
        log("tracing started: " + plan.followed.length + " threads followed");
        return { started: true, threads: plan.followed.length };
    },

    status: function () {
        return {
            redirects: stats.redirects,
            licenseMapped: plan.licMapped,
            mappedTo: report.licenseMappedTo || null,
            candidates: Object.keys(plan.copySet).length,
            licCopy: plan.licCopy,
            byteWrites: stats.byteWrites,
            byteStoresPlanned: stats.byteStoresPlanned,
            byteStoresSystem: stats.byteStoresSystem,
            byteWritesFromMem: stats.byteWritesFromMem,
            rwNoMap: stats.rwNoMap,
            rwNoTid: stats.rwNoTid,
            rwNoByte: stats.rwNoByte,
            rwByteMismatch: stats.rwByteMismatch,
            instructions: stats.instructions,
            inside: stats.inside,
            outside: stats.outside,
            threads: threadStates(),
            originalLicensePath: report.originalLicensePath || null,
            fileOpens: stats.fileOpens,
            openedPaths: report.openedPaths.slice(0, 6),
            stage1Sub: plan.stage1.sub,
            stage1GuardHits: plan.stage1.guardHits,
            stage1GuardArmed: plan.stage1.guardArmed,
            stage1CollateralReads: plan.stage1.collateralReads,
            stage1Rearms: plan.stage1.rearms,
            stage1HwBreakActive: plan.hwBreakActive,
            stage1HwBreakHits: plan.hwBreakHits,
            messageBoxes: plan.messageBoxes || 0,
            stage2Sub: plan.stage2 === undefined ? 0 : plan.stage2.sub,
            stage2Hash3: plan.stage2 === undefined
                ? null : plan.stage2.realHash3,
            stage2CmpCandidates: plan.stage2 === undefined
                ? 0 : plan.stage2.cmpCandidates,
            stage2Hits: plan.stage2 === undefined ? 0 : plan.stage2.hits,
            stage1Complete: report.stage1Complete === true,
            stage1MpExptmod: plan.stage1.mpExptmod,
            stage1DecLic: plan.stage1.decLic,
            stage1Calls: plan.stage1.callCount,
            retToRsa: plan.stage1.retToRsa
        };
    },

    finish: function () {
        stats.elapsedMs = Date.now() - followStart;
        report.stats = stats;
        report.candidates = Object.keys(plan.copySet);
        try {
            for (const id of plan.followed) {
                Stalker.unfollow(id);
            }
            Stalker.flush();
            Stalker.garbageCollect();
            report.unfollowed = true;
        } catch (e) {
            report.errors.push("unfollow: " + String(e));
        }
        for (const hook of plan.hooks) {
            try {
                hook.detach();
            } catch (e) {
                /* already gone */
            }
        }
        report.licMapped = plan.licMapped;
        report.stage1 = {
            sub: plan.stage1.sub,
            preRsaBuf: plan.stage1.preRsaBuf
                ? plan.stage1.preRsaBuf.toString() : null,
            retToRsa: plan.stage1.retToRsa,
            decLic: plan.stage1.decLic,
            retSlotOffset: plan.stage1.retSlotOffset,
            retCandidatesInModule: plan.stage1.retCandidatesInModule,
            keyRef: plan.stage1.keyRef ? plan.stage1.keyRef.toString() : null,
            keyRefReads: plan.stage1.keyRefReads,
            mpExptmod: plan.stage1.mpExptmod,
            lastCall: plan.stage1.lastCall,
            callCount: plan.stage1.callCount,
            decSections: plan.stage1.decSections,
            complete: report.stage1Complete === true
        };
        return report;
    }
};
