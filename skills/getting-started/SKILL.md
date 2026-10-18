---
name: getting-started
description: Use on first install of VeilBreaker, or when the owner asks how to set it up. Install the plugin, set the mode, confirm the MCP server is connected, run the first scan, run report, open the local dashboard, and run the self-test.
---
# Getting started with VeilBreaker

**Step 0:** after setup, every read and every outbound action follows [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md).

## 1. Install
Install the VeilBreaker plugin (repo: https://github.com/shagghiesuperstar/veilbreaker). There are no dependencies; it needs Node ≥ 18. The plugin's `mcp.json` starts the server over stdio: `node ${CURSOR_PLUGIN_ROOT}/server/index.mjs`.

## 2. Configure and connect
Set `VEILBREAKER_MODE`: `shadow` (the default: a deny is recorded to the event log and reported to the owner) or `strict` (same, and the bot is expected to stop the action on deny). VeilBreaker cannot block host tools itself in either mode. Other optional settings: `VEILBREAKER_LOG` (event log path, default `~/.veilbreaker/events.jsonl`; `off` disables it), `VEILBREAKER_PIN_FILE`, `VEILBREAKER_MAX_INPUT`.

Confirm the `veilbreaker` MCP server is connected and lists 8 tools: `safe_fetch`, `reveal`, `scan`, `egress_check`, `mcp_pin`, `mcp_verify`, `report`, `ttp_catalog`. Upgrading from 0.2.x: the host caches the tool list from install time. Remove and re-add the `veilbreaker` connector (a restart is not enough) so `report` appears; until then run `node server/index.mjs --cli report` on the same log.

## 3. First scan
1. `ttp_catalog` to list what is covered.
2. `scan` on a short sample. Expected verdicts: `clean`, `review` (a heads-up), `suspicious` (stop and ask), or `unsupported` (binary input).
3. `safe_fetch` on a public page you trust. The content comes back inside `<<UNTRUSTED_…>>` markers.
4. `mcp_pin` with the tool definitions of each connected MCP server, so later `mcp_verify` runs can detect changes.
5. `report` (for example `since` = `24h`). It counts the calls you just made from the metadata-only event log; an empty log says "0 events".
6. Open the dashboard: `node <plugin-root>/server/index.mjs --cli dashboard --since 7d` writes one self-contained `veilbreaker-dashboard.html` (no scripts, no network requests). `--cli serve-dashboard` serves it on 127.0.0.1:8790 only. Keep it local; never publish it to the internet.
7. Optional: `node <plugin-root>/server/index.mjs --cli selftest` prints pass/fail counts for the built-in fixtures.

## Known limits
VeilBreaker flags concealment mechanisms, not intent. Reworded and split payloads are out of scope; pair it with a classifier. It cannot intercept host built-in tools, so the step-0 skill is how reads and sends get routed through it. The event log only sees calls made to VeilBreaker's own tools.

## Citation
See `ttp_catalog` for per-technique sources (e.g. arXiv:2302.12173 for indirect prompt injection).
