# VeilBreaker

**Deterministic, zero-dependency coverage of the latest documented (2025–2026) prompt-injection concealment and exfiltration TTPs. Built to pair with an ML classifier.**

VeilBreaker is a zero-dependency Node MCP plugin of deterministic tools and skills. No model is involved in any decision. Every finding carries a severity and an id. Every TTP finding also carries a citation; operational notes (VB-I01 size cap, VB-I02 unsupported input) do not.

## Honest scope
- VeilBreaker **does not stop every prompt injection**. It targets specific, documented techniques that hide instructions or smuggle data out.
- **Out of scope:** reworded or purely semantic attacks in plain visible text, and **split / multi-message payloads** (an attack spread across several messages, files, pages or tool results that only becomes harmful when combined). Each `scan` call looks at one input on its own. Images, audio and PDFs are also out of scope: binary input returns `unsupported`.
- These limits are deliberate. Adaptive attacks defeat learned detectors (arXiv:2602.05746, 2507.07417, 2606.15057), so VeilBreaker only makes claims it can test with fixed rules.
- VeilBreaker is **strongest when reads go through `safe_fetch`**. The host's built-in web/fetch tools and other connectors cannot be intercepted by a plugin (see *Runtime findings*), so content read any other way is only covered if the bot passes it to `scan`/`reveal` as the `step-0-untrusted-content` skill instructs.
- `safe_fetch` has an SSRF guard. It resolves every address and refuses loopback, private (RFC1918), CGNAT, link-local/metadata, ULA (fc00::/7), 0.0.0.0/8 and IPv4-mapped forms, plus metadata/local hostnames. `198.18.0.0/15` (the RFC 2544 benchmarking range) is deliberately allowed, because fake-IP DNS setups (proxy/VPN clients that map public hostnames into that range) need it to reach public sites. It follows redirects manually, re-checks each hop (max 5), and connects to the exact IP it validated, so a DNS answer that changes after the check cannot redirect the request. It cannot see past an outbound proxy (see CHANGELOG 0.2.3).
- `safe_fetch` does not decompress. A response with any `Content-Encoding` other than `identity` (gzip, deflate, br, or a list of codings) is not decompressed or scanned. It returns verdict `unsupported`, with a reason that says the body is encoded and NOT scanned, and 0 findings. `unsupported` means NOT scanned, not clean. Decompression is deliberately unsupported in this release because of the zip-bomb risk; it may be added later.
- `egress_check` is advisory. It defaults to **shadow** (`VEILBREAKER_MODE=shadow`): a `deny` is recorded to the event log (metadata only) and reported to the user with reasons, and the bot or a human has to stop the action. `strict` mode only changes the wording of the advice (the bot is expected to stop on deny). In both modes VeilBreaker still **cannot block host tools itself**. With `VEILBREAKER_LOG=off` nothing is recorded, and the `handling` text says so.
- The event log only sees calls made to VeilBreaker's own tools. Content the host reads or sends without calling VeilBreaker never appears in the log, `report` or the dashboard. The log holds no raw content, but the `input_sha256` of a short or guessable input can be confirmed by someone who guesses it.

## Measured results
- Independent held-out benchmark (5,120 samples in total, never seen by the builder): v0.2 flagged 1,634 of 2,242 disguised injections (72.9%) as suspicious, vs 797 of 2,242 (35.6%) for v0.1.
- 0 of 320 realistic legitimate-use samples were flagged suspicious (8 categories × 40 samples: emoji ZWJ sequences, emoji tag flags, Arabic/Hebrew with bidi marks, Persian/Hindi with ZWNJ, Russian/Greek sentences, base64 data: URI images, hex colors/hashes, ordinary HTML alt/aria/comments).
- Real web pages can land in "review" because of hidden UI text (e.g. "Enable JavaScript…"). "review" is a heads-up, not an alarm.
- VeilBreaker flags concealment mechanisms, not intent. Reworded and split payloads are out of scope.

## Verdicts
`scan` returns `clean`, `review` (a medium finding: look before acting), `suspicious` (a high or critical finding), or `unsupported` (binary / non-UTF-8 input). Low findings are notes and leave the verdict `clean`. Inputs over the size cap (default 1,000,000 characters, `VEILBREAKER_MAX_INPUT`) are cut, return `truncated: true`, and add a VB-I01 finding (medium).

## Tools
| Tool | What it does |
|---|---|
| `safe_fetch(url)` | Fetches http(s), returns visible text plus **unmasked hidden material**, fenced as UNTRUSTED with a random per-call boundary (spotlighting; `datamark: true` for datamarking), and scan findings. |
| `reveal(text\|html)` | All views: raw; NFKC + zero-width/bidi stripped; Unicode TAG chars decoded to ASCII; bounded base64/hex/rot13/url/entity decodes (depth ≤ 2, 64 KB cap); HTML visible vs hidden text (comments, `display:none`, `visibility:hidden`, zero-size, opacity 0, off-screen, white-on-white best effort, `alt`, `aria-*`, `title`, `meta`, hidden inputs, `data-*`). |
| `scan(text\|html)` | Concealment findings: tag smuggling, zero-width, bidi override, mixed-script/homoglyph, encoded payloads, chat-template/role tokens, memory-persistence and self-replication directives, and the **key signal**: instruction-like text that appears **only** in a hidden or decoded view. |
| `egress_check(sink, args, context)` | Denies when a URL / markdown image / link / unfurl / DNS name / email recipient / tool argument carries secret-looking or session-private data (plain, URL-, base64- or hex-encoded), or when the destination came from untrusted content. Covers EchoLeak reference-style images, URL-path, query and DNS-subdomain exfil, open redirects via allowlisted domains. |
| `mcp_pin(definitions)` / `mcp_verify(definitions)` | sha256 over canonical name+description+schema per server; flags tool-description poisoning, cross-server name collision/shadowing, and rug pulls (changed after approval). |
| `report(since?, group_by?)` | Counts from the metadata-only event log: calls, verdicts, egress deny vs allow (and shadow-only denies), top TTPs with names and citations, top hosts, `mcp_verify` changes, `log_path`, `first_event` / `last_event`. An empty log returns explicit zeros and "0 events". |
| `ttp_catalog()` | The covered-TTP list below, with citations. |

## Activity log, report and dashboard (v0.3.0)
A fresh install lists 8 tools. When upgrading, Grok Bot may keep the old tool list (removing and re-adding under the same name, or restarting, did not refresh it in our test); if `report` is missing, add the connector under a new name, then remove the old `veilbreaker` connector (so two connectors never write to one log); or run `node server/index.mjs --cli report` on the same log.

- **Event log.** Every MCP tool call appends one JSON line to `VEILBREAKER_LOG` (default `~/.veilbreaker/events.jsonl`; `VEILBREAKER_LOG=off` disables it). Fields: `ts`, `tool`, `verdict`, `decision`, `mode`, `max_severity`, `ttps`, `sink`, `host`, `input_sha256`, `input_chars`, `duration_ms`, `version`; plus `reasons` (egress reason codes), `mcp_changes` (`mcp_verify`) and `error` when a call failed. `host` is the registrable domain only (subdomain labels can carry DNS-exfil data), and IP literals are never logged: they become `<ipv4-blocked>`, `<ipv4-public>`, `<ipv6-blocked>` or `<ipv6-public>` (blocked = any range the SSRF guard refuses, including loopback, private, link-local and the TEST-NET documentation ranges); email recipients are never logged. Raw input, page text, arguments, URLs with paths or queries, emails and secrets are never stored, and a test plants a secret and an email and checks neither reaches the log. The log rotates at 10 MB and keeps one old file (`events.jsonl.1`). A failed log write never breaks the tool call; it comes back as an extra `note` text block. `report` calls are not logged, so a quiet day reads "0 events". CLI commands are not logged, and the egress `handling` text says so: an MCP call says a deny is recorded, a `--cli egress` run says "CLI runs are not recorded to the event log", and a direct library call says it is not recorded.
- **`report`** `{since?: ISO | "24h" | "7d", group_by?: "ttp" | "tool" | "host" | "day"}` reads the log (current and rotated file).
- **Dashboard.** `node server/index.mjs --cli dashboard [--since 7d] [--out veilbreaker-dashboard.html]` writes one self-contained static HTML file: inline CSS, inline SVG bars, no scripts, no external resources, no network requests, no raw content (a Content-Security-Policy of `default-src 'none'` is embedded as well). It shows totals, deny/suspicious per UTC day, top TTPs with catalog names and citations (plain text), top hosts, MCP pin changes, mode, log path and the generated-at time.
- **Live dashboard.** `node server/index.mjs --cli serve-dashboard [--port 8790] [--since 7d]` binds **127.0.0.1 only** and regenerates the page on each request. A non-loopback bind is refused unless `--bind <addr>` is given explicitly, and then a warning is printed. Requests whose Host header is not a loopback name are refused (DNS-rebinding guard). Never publish the dashboard to the internet.
- `node server/index.mjs --cli report [--since 24h] [--group-by ttp]` prints the same JSON as the tool.

## Covered TTPs
This table mirrors `ttp_catalog()` exactly (ID, kind, name and default severity; a test enforces it). Each citation was fetched and its title confirmed on 2026-10-16. `kind: ttp` rows are techniques; `operational` rows (VB-I01, VB-I02) are notes about the input and carry no citation; `design` rows explain the approach. Severities are the defaults `scan` / `mcp_verify` assign; `egress_check` returns allow/deny.

| ID | Kind | Technique | Default severity | Source |
|---|---|---|---|---|
| VB-T01 | ttp | Unicode TAG smuggling (U+E0000–E007F) | high (critical if the payload is agent-directed) | [arXiv:2504.11168](https://arxiv.org/abs/2504.11168) Bypassing LLM Guardrails |
| VB-T02 | ttp | Zero-width character injection / ZW binary encoding | high when inside words above density threshold or a run of 8+; low for stray chars; emoji ZWJ and Arabic/Persian/Indic joiners exempt | arXiv:2504.11168 |
| VB-T03 | ttp | Bidi override / embedding (Trojan-Source style) | high for LRO/RLO/LRE/RLE/PDF; low for RLM/LRM/isolates in RTL text; medium without RTL text | arXiv:2504.11168 |
| VB-T04 | ttp | Homoglyph: mixed scripts within one word; NFKC compat chars | high | arXiv:2504.11168 |
| VB-T05 | ttp | Encoded payloads (base64/hex/rot13/url/entities, depth ≤2) | high when decoded text is agent-directed or has role tokens | arXiv:2504.11168 |
| VB-T06 | ttp | Chat-template / role-token smuggling | high | [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) Indirect Prompt Injection |
| VB-T07 | ttp | Injection phrase in hidden HTML (phrase list, extra signal) | high (low if the same text is visible) | arXiv:2302.12173 |
| VB-T08 | ttp | KEY SIGNAL: text present ONLY in a hidden or decoded view | medium/review for substantive concealed text; critical/suspicious when agent-directed; descriptive alt/title/aria/meta and dev comments clean | arXiv:2302.12173 |
| VB-T09 | ttp | Decode-and-follow wrapper | high | arXiv:2504.11168 |
| VB-E01 | ttp | EchoLeak zero-click markdown-image exfil (incl. reference-style) | deny | [CVE-2025-32711](https://www.cve.org/CVERecord?id=CVE-2025-32711), [arXiv:2509.10540](https://arxiv.org/abs/2509.10540) |
| VB-E02 | ttp | Covert exfil via URL path / query / DNS subdomain through legit fetching | deny | [arXiv:2610.01768](https://arxiv.org/abs/2610.01768) The Innocent Courier |
| VB-E03 | ttp | Open redirect via allowlisted domain | deny | arXiv:2610.01768 |
| VB-E04 | ttp | Link unfurl / auto-fetch exfil | deny | CVE-2025-32711, arXiv:2509.10540 |
| VB-E05 | ttp | Secrets / session-private data in outbound args (plain, url, base64, hex) | deny | [CaMeL 2503.18813](https://arxiv.org/abs/2503.18813), [FIDES 2505.23643](https://arxiv.org/abs/2505.23643), [Progent 2504.11703](https://arxiv.org/abs/2504.11703) |
| VB-E06 | ttp | Destination or recipient sourced from untrusted content | deny | CaMeL, FIDES, Progent |
| VB-M01 | ttp | MCP tool-description poisoning | high | [Invariant Labs, Tool Poisoning Attacks (2025-04-01)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [arXiv:2508.13220](https://arxiv.org/abs/2508.13220), [arXiv:2506.02040](https://arxiv.org/abs/2506.02040) |
| VB-M02 | ttp | MCP tool shadowing / name collision across servers | high | same |
| VB-M03 | ttp | MCP rug pull (definition changed after approval) | critical (new tool high, removed low) | same |
| VB-P01 | ttp | Persistent / sleeper memory poisoning | high when hidden, medium when visible | [arXiv:2609.13889](https://arxiv.org/abs/2609.13889), [arXiv:2605.15338](https://arxiv.org/abs/2605.15338) |
| VB-P02 | ttp | Agent worm / self-replicating prompts | high | [arXiv:2403.02817](https://arxiv.org/abs/2403.02817) |
| VB-I01 | operational | Input over size cap | medium | none (operational note) |
| VB-I02 | operational | Binary / non-text input | info (verdict unsupported) | none (operational note) |
| VB-D01 | design | Design basis: adaptive attacks defeat learned detectors | n/a | [2602.05746](https://arxiv.org/abs/2602.05746), [2507.07417](https://arxiv.org/abs/2507.07417), [2606.15057](https://arxiv.org/abs/2606.15057) |
| VB-D02 | design | Design basis: capability / information-flow control | n/a | CaMeL, FIDES, Progent |

## Runtime findings (Step 0, inspected 2026-10-16 on a Grok Bot box)
1. **Pre-read hooks:** the installed Grok Bot plugin cache uses the Cursor plugin layout (tools via `mcp.json`, `skills/`). One plugin ships a `hooks/hooks.json` with `PreToolUse`/`SessionEnd` command hooks, but there is no evidence of a hook that sees content *before the bot reads it* (no post-tool/response hook). Whether the Grok Bot host executes plugin hooks at all is **unknown**. VeilBreaker therefore uses the tools + skills design and ships no hooks.
2. **Install / sandbox:** plugins are cached under `~/agent-data/plugins/cache/<source>/<name>/<sha>/`; MCP servers run as local stdio processes. Node v20.19.2 observed. Sandbox limits beyond that are unknown. VeilBreaker needs Node ≥ 18 and no network except `safe_fetch`.
3. **Built-in web fetch:** a host tool. A plugin cannot replace or wrap it; `safe_fetch` is a parallel tool the skill tells the bot to prefer.
4. **Daily untrusted input:** web pages and search results, email, user files and attachments, MCP connector output (Notion, Linear, PostHog, GitHub, X, etc.), and messages from other bots.

## Install
Add as a Grok Bot / Cursor plugin (layout: `plugin.json`, `.cursor-plugin/plugin.json`, `mcp.json`, `skills/`). There are no dependencies, so no `npm install` is needed. Node ≥ 18.

## CLI (for benchmarking)
```
node server/index.mjs --cli scan <file|->      # JSON findings
node server/index.mjs --cli reveal <file|->
node server/index.mjs --cli egress <json-file>   # {"sink","args","context"}
node server/index.mjs --cli catalog
node server/index.mjs --cli selftest           # built-in fixtures, prints pass/fail counts (exit 1 on any failure)
node server/index.mjs --cli report [--since 24h] [--group-by ttp|tool|host|day]
node server/index.mjs --cli dashboard [--since 7d] [--out veilbreaker-dashboard.html]
node server/index.mjs --cli serve-dashboard [--port 8790] [--since 7d] [--bind <addr>]   # 127.0.0.1 unless --bind
```
The CLI works through symlinks. It always prints JSON. Exit codes: 0 = result printed (including `unsupported` and `truncated`); 2 = usage or input error (e.g. missing file) as `{"error": …}`, with no stack trace; 1 = internal error, also as JSON.

## Tests
```
npm test                          # same as: node --test tests/*.test.mjs
```
Every rule has an attack fixture that must be caught and a benign look-alike that must not be flagged (emoji ZWJ and tag-flag sequences, Hebrew/Arabic bidi text, Persian/Hindi joiners, Japanese mixed kana/kanji, single-script Cyrillic/Greek/Armenian words, data:image base64, hex hashes, descriptive alt/aria/meta text, developer comments, decoding tutorials). Egress has 12 exfil patterns that must be blocked and 12 benign flows that must be allowed. Tests point `VEILBREAKER_LOG` and `VEILBREAKER_PIN_FILE` at temp files (`tests/helpers/isolate-log.mjs`), so they never touch `~/.veilbreaker`.

## Grok Bot template
`grokbot-template/veilbreaker.template.json` is one "VeilBreaker Guard & Watch" bot (0.3.1: the Guard and Watch templates combined). It checks untrusted content and outbound data in flight (`safe_fetch`, `reveal`, `scan`, `egress_check`, `mcp_pin`, `mcp_verify`) and reports on a schedule (`report`, `ttp_catalog`, local dashboard): profile, 8 memories, 12 plugin skills copied verbatim, and 4 routines (daily 08:00 digest from `report`, weekly local dashboard file, daily MCP pin check, weekly self-test). See `grokbot-template/README.md`.

## License
MIT
