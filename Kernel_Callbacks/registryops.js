"use strict";

function resolveRegistryCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    log("[*] Walking nt!CallbackListHead registry callbacks:\n");

    let headRes = ctl.ExecuteCommand("dqs nt!CallbackListHead L1");
    let flink = "";
    for (let l of headRes) {
        let parts = l.trim().split(/\s+/);
        if (parts.length >= 2) {
            flink = parts[1].replace(/`/g, "");
            break;
        }
    }

    if (!flink) {
        log("[-] Failed to read CallbackListHead");
        return;
    }

    log("[*] Head Flink: 0x" + flink + "\n");

    let headAddrRes = ctl.ExecuteCommand("? nt!CallbackListHead");
    let headAddr = "";
    for (let l of headAddrRes) {
        let match = l.match(/=\s+([0-9a-f`]+)/i);
        if (match) {
            headAddr = match[1].replace(/`/g, "");
            break;
        }
    }

    let current = flink;
    let count = 0;
    let maxIter = 64;

    while (count < maxIter) {

        if (current === headAddr) {
            log("[*] Reached list head — done.\n");
            break;
        }

        log("[" + count + "] Entry: 0x" + current);

        let dpsRes = ctl.ExecuteCommand("dqs 0x" + current + " L7");
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

            if (i === 0) nextFlink    = val;           // offset 0x00 Flink
            if (i === 4) preCallback  = display;       // offset 0x20
            if (i === 5) postCallback = display;       // offset 0x28
        }

        // Only print non-null callbacks
        if (preCallback && !preCallback.startsWith("0000000000000000")) {
            log("    Pre  Callback (0x20): " + preCallback);
        }
        if (postCallback && !postCallback.startsWith("0000000000000000")) {
            log("    Post Callback (0x28): " + postCallback);
        }
        log("");

        if (!nextFlink || nextFlink === "0000000000000000") break;
        current = nextFlink;
        count++;
    }

    log("[*] Done. " + count + " entries walked.");
}

function initializeScript() {
    return [
        new host.functionAlias(resolveRegistryCallbacks, "resolveRegistryCallbacks")
    ];
}
