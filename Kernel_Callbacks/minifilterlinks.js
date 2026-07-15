"use strict";

function resolveMinifilterCallbackLinks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    log("[*] Enumerating Minifilter CALLBACK_NODE Flink/Blink links\n");

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
            instances.push({
                addr:   instanceMatch[1].replace(/`/g, ""),
                name:   instanceMatch[2],
                filter: currentFilter
            });
        }
    }

    log("[+] Found " + instances.length + " filter instances\n");

    for (let i = 0; i < instances.length; i++) {
        let inst = instances[i];

        log("--------------------------------------------------");
        log("[" + i + "] Filter:   " + inst.filter);
        log("[" + i + "] Instance: " + inst.name + " @ 0x" + inst.addr);

        let instRes = ctl.ExecuteCommand("!instance 0x" + inst.addr + " 4");

        let inCallbacks = false;

        for (let l of instRes) {
            let trimmed = l.trim();

            if (trimmed.startsWith("CallbackNodes")) {
                inCallbacks = true;
                continue;
            }

            if (!inCallbacks) continue;

            // Print operation headers
            if (trimmed.match(/^(CREATE|CLOSE|WRITE|READ|SET_INFORMATION|CLEANUP|CREATE_NAMED_PIPE|QUERY_INFORMATION|DIRECTORY_CONTROL|NETWORK_QUERY_OPEN|CREATE_MAILSLOT)/i)) {
                log("    " + trimmed);
            }

            // For each CALLBACK_NODE read and print its Flink and Blink
            let nodeMatch = trimmed.match(/CALLBACK_NODE:\s+([0-9a-f`]+)/i);
            if (nodeMatch) {
                let node = nodeMatch[1].replace(/`/g, "");

                let dpsRes = ctl.ExecuteCommand("dqs 0x" + node + " L2");
                let lines = [];
                for (let dl of dpsRes) {
                    let dt = dl.trim();
                    if (dt.length > 0) lines.push(dt);
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

                let isUnlinked = (flink === "0000000000000000" || blink === "0000000000000000");
                let status = isUnlinked ? " [UNLINKED]" : "";

                log("      CALLBACK_NODE: 0x" + node + status);
                log("        Flink: 0x" + flink);
                log("        Blink: 0x" + blink);
            }
        }

        log("");
    }

    log("[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(resolveMinifilterCallbackLinks, "resolveMinifilterCallbackLinks")
    ];
}
