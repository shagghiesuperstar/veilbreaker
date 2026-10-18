# In-app test kit (v0.2.3)

- **Server (stdio):** `/usr/bin/node /workspace/veilbreaker/server/index.mjs` (on the Grok Bot box; the plugin's `mcp.json` uses `node ${CURSOR_PLUGIN_ROOT}/server/index.mjs`).
- **Inputs:** `inputs.json`, plus `tag-string.txt`, which holds the Unicode-tag test string with its real invisible characters, for copy-paste.
- **Local baseline:** `node docs/in-app-test/run-baseline.mjs` drives the server over stdio JSON-RPC with the same inputs and writes `baseline-outputs.json` (pass/fail per call).
- **In-app results (2026-10-17):** scan, safe_fetch, egress_check, mcp_pin and mcp_verify (unchanged and tampered) all PASS through the Grok Bot `veilbreaker` connector. Details and exact outputs: [../IN-APP-TEST.md](../IN-APP-TEST.md).
