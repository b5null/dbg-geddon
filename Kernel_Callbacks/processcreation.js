"use strict";

function resolvePspCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    log("[*] PspCreateProcessNotifyRoutine callbacks:\n");

    let results = ctl.ExecuteCommand("dqs nt!PspCreateProcessNotifyRoutine L10");

    let addresses = [];

    for (let line of results) {
        let parts = line.trim().split(/\s+/);
        if (parts.length < 2) continue;
        let raw = parts[1].replace(/`/g, "");
        if (raw === "0000000000000000") break;
        addresses.push(raw);
    }

    for (let i = 0; i < addresses.length; i++) {
        let raw = addresses[i];

        let maskedRes = ctl.ExecuteCommand("? (" + raw + " & 0xFFFFFFFFFFFFFFF8)");
        let maskedStr = "";
        for (let l of maskedRes) {
            let match = l.match(/=\s+([0-9a-f`]+)/i);
            if (match) {
                maskedStr = match[1].replace(/`/g, "");
                break;
            }
        }

        if (!maskedStr) continue;

        // dps gives us the clean line we want
        let dpsRes = ctl.ExecuteCommand("dps 0x" + maskedStr + " L1");
        for (let l of dpsRes) {
            let trimmed = l.trim();
            if (trimmed.length > 0)
                log("[" + i + "] " + trimmed);
        }
    }

    log("\n[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(resolvePspCallbacks, "resolvePspCallbacks")
    ];
}
