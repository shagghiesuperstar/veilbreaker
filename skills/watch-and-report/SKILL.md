---
name: watch-and-report
description: Use when the owner asks what VeilBreaker has seen, for the daily digest or weekly dashboard routines, or after a critical finding. How to read the report tool, what counts as a spike, and how to generate and attach the local dashboard file.
---
# Watch and report on VeilBreaker activity

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Every call to a VeilBreaker tool appends one metadata-only line to the event log (`VEILBREAKER_LOG`, default `~/.veilbreaker/events.jsonl`): time, tool, verdict or decision, mode, max severity, TTP ids, egress sink, a reduced host (registrable domain only; IP literals become `<ipv4-blocked>` / `<ipv4-public>` / `<ipv6-blocked>` / `<ipv6-public>`, where blocked = any range the SSRF guard refuses), a sha256 of the input, its length, and the duration. It never stores raw input, page text, arguments, URLs with paths or queries, emails or secrets. The log rotates at 10 MB and keeps one old file. `report` calls are not logged, so a quiet day reads "0 events".

## Upgrading
A fresh install lists 8 tools. When upgrading, Grok Bot may keep the old tool list (removing and re-adding under the same name, or restarting, did not refresh it in our test); if `report` is missing, add the connector under a new name, then remove the old `veilbreaker` connector (so two connectors never write to one log); or run `node server/index.mjs --cli report` on the same log.

## How to read `report`
1. Call `report` with `since` (`24h`, `7d`, or an ISO date/time) and optionally `group_by` (`ttp`, `tool`, `host`, `day`).
2. Quote numbers only from the `report` output. Never estimate, round up, or fill gaps. If `calls` is 0, say "0 events" for that window.
3. Read these fields: `calls`; `verdicts` (suspicious, review, clean, unsupported from `scan` and `safe_fetch`); `egress` (deny vs allow, and `deny_shadow_only`: denies that VeilBreaker only recorded and reported, because it cannot block host tools); `top_ttps` (each with its catalog name and citation); `top_hosts`; `mcp_verify` (runs and definition changes); `first_event` / `last_event`; `log_path`.
4. `unsupported` means NOT scanned, not clean. `errors` counts tool calls that failed (for example a `safe_fetch` the SSRF guard refused).
5. If `log_enabled` is false, the log is off (`VEILBREAKER_LOG=off`): say so instead of reporting zeros as if nothing happened.

## What counts as a spike
- Any critical finding, any `mcp_verify` change, or any egress deny: tell the owner in the same turn, even outside a routine.
- A day with suspicious verdicts or egress denies at least 3 times its 7-day daily average (use `group_by` = `day` over `7d`), or 5 or more in one day when the average is under 1.
- A TTP or host that appears for the first time in the 7-day window.
- Report a spike with the numbers, the TTP names and citations from `report`, and the window. Do not guess at causes.

## Dashboard
- Generate: `node <plugin-root>/server/index.mjs --cli dashboard --since 7d --out veilbreaker-dashboard.html`. The result is one static HTML file: inline CSS and SVG, no scripts, no network requests, no raw content. Attach that file in chat.
- Live view: `node <plugin-root>/server/index.mjs --cli serve-dashboard --port 8790` binds 127.0.0.1 only and regenerates on each request. A non-loopback bind needs an explicit `--bind` and prints a warning; do not use it unless the owner asks.
- The dashboard is local. Never upload or publish it to the internet, a public link, or a shared drive.

## Known limits
The log only sees calls made to VeilBreaker's own tools; host built-in fetches and other connectors are invisible to it unless the bot routes them through VeilBreaker. A sha256 of a short or guessable input can be confirmed by guessing. Counts are per call, not per attack.

## Citation
Per-TTP sources come from `ttp_catalog` and appear in `report` `top_ttps` (e.g. arXiv:2302.12173 for indirect prompt injection).
