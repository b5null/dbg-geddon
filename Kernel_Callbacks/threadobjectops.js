"use strict";

function resolveThreadObjectCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    log("[*] Walking PsThreadType->CallbackList object callbacks:\n");

    // Step 1 — get _OBJECT_TYPE base from PsThreadType
    let ptrRes = ctl.ExecuteCommand("dqs nt!PsThreadType L1");
    let objTypeBase = "";
    for (let l of ptrRes) {
        let parts = l.trim().split(/\s+/);
        if (parts.length >= 2) {
            objTypeBase = parts[1].replace(/`/g, "");
            break;
        }
    }

    if (!objTypeBase) {
        log("[-] Failed to read PsThreadType");
        return;
    }

    log("[*] _OBJECT_TYPE base: 0x" + objTypeBase);

    // Step 2 — get CallbackList head at base + 0xc8
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

    // Step 3 — read Flink from head
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

    // Step 4 — walk the list
    let current = flink;
    let count = 0;
    let maxIter = 64;

    while (count < maxIter) {

        // Stop when we loop back to the list head
        if (current === headAddr) {
            log("[*] Reached list head - done.\n");
            break;
        }

        log("[" + count + "] Entry: 0x" + current);

        // Read 8 QWORDs from current entry
        // offset 0x00 = Flink
        // offset 0x08 = Blink
        // offset 0x28 = PreOperation  (index 5)
        // offset 0x30 = PostOperation (index 6)
        let dpsRes = ctl.ExecuteCommand("dqs 0x" + current + " L8");
        let lines = [];
        for (let l of dpsRes) {
            let trimmed = l.trim();
            if (trimmed.length > 0) lines.push(trimmed);
        }

        let nextFlink    = "";
        let preCallback  = "";
        let postCallback = "";

        for (let i = 0; i < lines.length; i++) {
            let parts = lines[i].split(/\s+/);
            if (parts.length < 2) continue;

            let val = parts[1].replace(/`/g, "");
            let sym = parts.slice(2).join(" ");
            let display = val + (sym ? " " + sym : "");

            if (i === 0) nextFlink     = val;
            if (i === 5) preCallback   = display;
            if (i === 6) postCallback  = display;
        }

        if (preCallback && !preCallback.startsWith("0000000000000000"))
            log("    Pre  Callback (0x28): " + preCallback);
        if (postCallback && !postCallback.startsWith("0000000000000000"))
            log("    Post Callback (0x30): " + postCallback);

        log("");

        if (!nextFlink || nextFlink === "0000000000000000") break;
        current = nextFlink;
        count++;
    }

    log("[*] Done. " + count + " entries walked.");
}

function initializeScript() {
    return [
        new host.functionAlias(resolveThreadObjectCallbacks, "resolveThreadObjectCallbacks")
    ];
}
