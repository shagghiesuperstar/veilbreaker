---
name: getting-started
description: Use on first install of VeilBreaker, or when the owner asks how to set it up. Install the plugin, confirm the MCP server is connected, run the first scan and the self-test.
---
# Getting started with VeilBreaker

**Step 0:** after setup, every read and every outbound action follows [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md).

## 1. Install
Install the VeilBreaker plugin (repo: https://github.com/shagghiesuperstar/veilbreaker). There are no dependencies; it needs Node ≥ 18. The plugin's `mcp.json` starts the server over stdio: `node ${CURSOR_PLUGIN_ROOT}/server/index.mjs`.

## 2. Connect
Confirm the `veilbreaker` MCP server is connected and lists 7 tools: `safe_fetch`, `reveal`, `scan`, `egress_check`, `mcp_pin`, `mcp_verify`, `ttp_catalog`. Optional settings: `VEILBREAKER_MODE` (`shadow`, the default, or `strict`), `VEILBREAKER_PIN_FILE`, `VEILBREAKER_MAX_INPUT`.

## 3. First scan
1. `ttp_catalog` to list what is covered.
2. `scan` on a short sample. Expected verdicts: `clean`, `review` (a heads-up), `suspicious` (stop and ask), or `unsupported` (binary input).
3. `safe_fetch` on a public page you trust. The content comes back inside `<<UNTRUSTED_…>>` markers.
4. `mcp_pin` with the tool definitions of each connected MCP server, so later `mcp_verify` runs can detect changes.
5. Optional: `node <plugin-root>/server/index.mjs --cli selftest` prints pass/fail counts for the built-in fixtures.

## Known limits
VeilBreaker flags concealment mechanisms, not intent. Reworded and split payloads are out of scope; pair it with a classifier. It cannot intercept host built-in tools, so the step-0 skill is how reads and sends get routed through it.

## Citation
See `ttp_catalog` for per-technique sources (e.g. arXiv:2302.12173 for indirect prompt injection).
