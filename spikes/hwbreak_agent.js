'use strict';

/*
 * Hardware-breakpoint landmark for whatlicense Stage 1 sub-stage 1.
 *
 * The guard-page route (spikes/spike2_agent.js) has to filter collateral
 * reads, because a guard page is page-granular and the program's license
 * structure shares its page with unrelated heap objects. A debug-register
 * breakpoint is exact: it fires only when the watched address is touched, so
 * there is no collateral traffic and nothing to re-arm.
 *
 * Windows gives four data breakpoints (DR0-DR3). We use three, one per
 * byte-store candidate the Stage 0 trace produced (for drchost those were
 * 0x608b80, 0x608bb7 and 0x608d30 for a 465-byte license).
 *
 * DR7 encoding used here:
 *   Ln  (local enable)  bit 2n        -- set for n = 0,1,2
 *   RWn (break on)      bits 16+4n..17+4n, 0b11 = read or write
 *   LENn (length)       bits 18+4n..19+4n, 0b00 = 1 byte (no alignment
 *                       requirement; any access overlapping the byte fires)
 * => DR7 = 0b011_0011_0011_0011_0001_0101 = 0x3330015
 *
 * The hit surfaces as EXCEPTION_SINGLE_STEP (0x80000004), which Frida reports
 * as type 'single-step'. Frida's CpuContext exposes no debug registers, so
 * Dr6 is not consulted -- we set these breakpoints ourselves and clear them
 * as soon as the landmark is taken, which is what makes that safe.
 *
 * CONTEXT layout (offsets are fixed by the ABI):
 *   x64: ContextFlags 0x30, Dr0 0x48, Dr1 0x50, Dr2 0x58, Dr3 0x60,
 *        Dr6 0x68, Dr7 0x70.  CONTEXT_DEBUG_REGISTERS = 0x00100010
 *   x86: ContextFlags 0x00, Dr0 0x04, Dr1 0x08, Dr2 0x0C, Dr3 0x10,
 *        Dr6 0x14, Dr7 0x18.  CONTEXT_DEBUG_REGISTERS = 0x00010010
 */

const CONTEXT_DEBUG_REGISTERS_X64 = 0x00100010;
const CONTEXT_DEBUG_REGISTERS_X86 = 0x00010010;

const THREAD_GET_CONTEXT = 0x0008;
const THREAD_SET_CONTEXT = 0x0010;
const THREAD_SUSPEND_RESUME = 0x0002;
const THREAD_QUERY_INFORMATION = 0x0040;
const THREAD_ACCESS = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;

/* DR7 for three 1-byte read/write breakpoints. */
const DR7_THREE_RW_BYTE = 0x03330015;

const CONTEXT_BUF_SIZE = 0x800;

function hwBreakLayout() {
    const is64 = Process.pointerSize === 8;
    return is64
        ? { flags: 0x30, dr0: 0x48, dr1: 0x50, dr2: 0x58, dr3: 0x60,
            dr6: 0x68, dr7: 0x70,
            contextFlags: CONTEXT_DEBUG_REGISTERS_X64 }
        : { flags: 0x00, dr0: 0x04, dr1: 0x08, dr2: 0x0c, dr3: 0x10,
            dr6: 0x14, dr7: 0x18,
            contextFlags: CONTEXT_DEBUG_REGISTERS_X86 };
}

/* Resolve an export across the modules that can carry it.
 *
 * Module.getExportByName throws when the module does not export the name, and
 * CloseHandle did not resolve from kernel32 alone in this process -- the lookup
 * produced something that was not callable, and the TypeError landed in a finally
 * block where it masked a successful install. Try the usual carriers. */
function hwBreakExport(name) {
    const modules = ["kernel32.dll", "KernelBase.dll", "ntdll.dll"];
    for (const moduleName of modules) {
        try {
            const address = Module.getExportByName(moduleName, name);
            if (address !== null && address !== undefined) {
                return address;
            }
        } catch (e) {
            /* not exported here; try the next module */
        }
    }
    return null;
}

function hwBreakApis() {
    if (hwBreakApis.cache !== undefined) {
        return hwBreakApis.cache;
    }
    const kernel32 = hwBreakExport("OpenThread");
    hwBreakApis.cache = {
        OpenThread: new NativeFunction(kernel32, "pointer",
            ["uint32", "int", "uint32"]),
        CloseHandle: new NativeFunction(hwBreakExport("CloseHandle"), "int",
            ["pointer"]),
        SuspendThread: new NativeFunction(hwBreakExport("SuspendThread"),
            "uint32", ["pointer"]),
        ResumeThread: new NativeFunction(hwBreakExport("ResumeThread"),
            "uint32", ["pointer"]),
        GetThreadContext: new NativeFunction(hwBreakExport("GetThreadContext"),
            "int", ["pointer", "pointer"]),
        SetThreadContext: new NativeFunction(hwBreakExport("SetThreadContext"),
            "int", ["pointer", "pointer"]),
        GetLastError: new NativeFunction(hwBreakExport("GetLastError"),
            "uint32", [])
    };
    return hwBreakApis.cache;
}

/* Write Dr0/Dr1/Dr2 and Dr7 for one thread.
 *
 * Deliberately does NOT suspend the thread and does NOT call
 * GetThreadContext. Suspending would deadlock whenever the target is the
 * current thread (it can never reach the matching ResumeThread), and
 * GetThreadContext on the current thread returns a stale context anyway.
 * SetThreadContext with ContextFlags = CONTEXT_DEBUG_REGISTERS writes only
 * the debug registers, so the rest of the context is left alone.
 */
function hwBreakApplyToThread(tid, addresses, enable) {
    /* Every step is labelled.
     *
     * Round 35 finally said what the failure is -- "TypeError: not a function" --
     * but not where, and the same run had some threads throwing and others
     * returning false, which no single call site explains. A step label turns the
     * next round into the line number. */
    let step = "hwBreakApis";
    try {
        const api = hwBreakApis();
        step = "hwBreakLayout";
        const layout = hwBreakLayout();
        step = "OpenThread";
        const handle = api.OpenThread(THREAD_ACCESS, 0, tid);
        if (handle.isNull()) {
            hwBreakApplyToThread.lastError =
                "tid=" + tid + " OpenThread err=" + api.GetLastError();
            return false;
        }
        let ok = false;
        try {
            step = "alloc";
            const ctx = Memory.alloc(CONTEXT_BUF_SIZE);
            step = "zero";
            ctx.writeByteArray(new Uint8Array(CONTEXT_BUF_SIZE));
            /* ContextFlags is a FIELD at layout.flags (0x30 on x64), not
             * offset 0. Writing the value at offset 0 left the real
             * ContextFlags field zero and SetThreadContext rejected the
             * context. */
            step = "ContextFlags";
            ctx.add(layout.flags).writeU32(layout.contextFlags);
            if (enable) {
                step = "Dr0";
                ctx.add(layout.dr0).writePointer(addresses[0] || ptr(0));
                step = "Dr1";
                ctx.add(layout.dr1).writePointer(addresses[1] || ptr(0));
                step = "Dr2";
                ctx.add(layout.dr2).writePointer(addresses[2] || ptr(0));
                step = "Dr7";
                ctx.add(layout.dr7).writePointer(ptr(DR7_THREE_RW_BYTE));
            }
            step = "SetThreadContext";
            ok = api.SetThreadContext(handle, ctx).toInt32() !== 0;
            if (!ok) {
                step = "GetLastError";
                hwBreakApplyToThread.lastError =
                    "tid=" + tid + " SetThreadContext err=" + api.GetLastError();
            }
        } finally {
            /* Closing is best effort, and must never mask a successful install.
             *
             * CloseHandle is the one export here that Frida's getExportByName
             * does not resolve to a callable in this process, and because the
             * call sat in the finally block its TypeError turned every successful
             * SetThreadContext into a reported failure -- which is why applied
             * was 0 on every run since the hardware breakpoint was first tried.
             * A leaked thread handle is harmless: the process is short-lived. */
            try {
                api.CloseHandle(handle);
            } catch (e) {
                /* leaked handle; not worth failing the install over */
            }
        }
        return ok;
    } catch (e) {
        hwBreakApplyToThread.lastError =
            "tid=" + tid + " at " + step + ": " + String(e);
        return false;
    }
}

/* Install on every thread that exists right now. Threads created later are
 * not covered -- for drchost the license read happens on the thread that
 * unmapped the license, which already exists at this point. */
function hwBreakInstall(plan, addresses) {
    const targets = addresses.filter(function (a) {
        return a !== null && a !== undefined;
    });
    if (targets.length === 0) {
        plan.emit({ spike: "hwbreak", event: "no-addresses" });
        return false;
    }
    let applied = 0;
    let failed = 0;
    const reasons = [];
    for (const thread of Process.enumerateThreads()) {
        let ok = false;
        try {
            ok = hwBreakApplyToThread(thread.id, targets, true);
        } catch (e) {
            ok = false;
            if (reasons.length < 3) {
                reasons.push("threw: " + String(e));
            }
        }
        if (ok) {
            applied++;
            plan.hwBreakThreads.push(thread.id);
        } else {
            failed++;
            if (reasons.length < 3) {
                reasons.push(hwBreakApplyToThread.lastError || "returned false");
            }
        }
    }
    plan.hwBreakActive = applied > 0;
    plan.emit({ spike: "hwbreak", event: "installed",
                addresses: targets.map(String),
                applied: applied, failed: failed,
                reasons: reasons,
                dr7: "0x" + DR7_THREE_RW_BYTE.toString(16) });
    return plan.hwBreakActive;
}

function hwBreakRemove(plan) {
    if (!plan.hwBreakActive) {
        return;
    }
    for (const tid of plan.hwBreakThreads) {
        try {
            hwBreakApplyToThread(tid, [], false);
        } catch (e) {
            /* best effort */
        }
    }
    plan.hwBreakActive = false;
    plan.hwBreakThreads = [];
    plan.emit({ spike: "hwbreak", event: "removed" });
}

/* Handler for EXCEPTION_SINGLE_STEP. Returns true when the exception was one
 * of our data breakpoints, false to let it reach the target. */
function hwBreakOnException(plan, details) {
    /* Stage 2's data breakpoint first, and independently of Stage 1's landmark.
     *
     * It is armed after Stage 1 completes and it is the only thing that knows
     * about it, so it must not be gated on plan.hwBreakActive (Stage 1 clears
     * that when it takes its landmark). */
    const s2 = plan.stage2;
    if (s2 !== undefined && s2.hw3Address !== undefined &&
        details.type === "single-step") {
        s2.hw3Hits = (s2.hw3Hits || 0) + 1;
        const pc = String(details.context[plan.PC_REG]);
        let text = "?";
        try {
            text = Instruction.parse(ptr(pc)).toString();
        } catch (e) {
            /* leave the marker */
        }
        plan.emit({ spike: "stage2", event: "hw3-hit", detail: "#" + s2.hw3Hits +
            " pc=" + pc + " insn=" + text + " ours=0x" +
            s2.hash3.toString(16) });
        if (s2.hw3Hits >= 3) {
            for (const tid of (s2.hw3Threads || [])) {
                try {
                    hwBreakApplyToThread(tid, [null, null, null], false);
                } catch (e) {
                    /* best effort */
                }
            }
            s2.hw3Address = undefined;
            plan.emit({ spike: "stage2", event: "hw3-removed",
                        detail: "#" + s2.hw3Hits });
        }
        return true;
    }
    if (!plan.hwBreakActive) {
        return false;
    }
    if (details.type !== "single-step") {
        return false;
    }
    plan.hwBreakHits = (plan.hwBreakHits || 0) + 1;
    const ctx = details.context || null;
    if (ctx === null) {
        /* Cannot read the stack without a context; drop the breakpoints so
         * the thread cannot spin on them. */
        hwBreakRemove(plan);
        return true;
    }
    /* Which address fired is not readable (Frida exposes no Dr6), but it does
     * not matter: what sub-stage 1 needs is the return address sitting on the
     * stack at the moment the license is touched. */
    plan.emit({ spike: "hwbreak", event: "hit",
                n: plan.hwBreakHits, pc: String(ctx[plan.PC_REG]) });
    hwBreakRemove(plan);
    plan.onHwBreakLandmark(ctx);
    return true;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        DR7_THREE_RW_BYTE,
        hwBreakInstall,
        hwBreakRemove,
        hwBreakOnException
    };
}