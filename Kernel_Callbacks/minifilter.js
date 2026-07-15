"use strict";

function resolveMinifilterCallbacks() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const ctl = host.namespace.Debugger.Utility.Control;

    log("[*] Enumerating Minifilter Callbacks via !fltkd.filters\n");

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

            if (
                trimmed.match(/^(CREATE|CLOSE|WRITE|READ|SET_INFORMATION|CLEANUP|CREATE_NAMED_PIPE|QUERY_INFORMATION|DIRECTORY_CONTROL|NETWORK_QUERY_OPEN|CREATE_MAILSLOT)/i) ||
                trimmed.startsWith("CALLBACK_NODE")
            ) {
                log("    " + trimmed);
            }
        }

        log("");
    }

    log("[*] Done.");
}

function initializeScript() {
    return [
        new host.functionAlias(resolveMinifilterCallbacks, "resolveMinifilterCallbacks")
    ];
}
