# Changelog

## 0.2.4 (unreleased)
- **Fix:** `safe_fetch` now fails loudly on encoded responses. A response with a `Content-Encoding` other than `identity` (gzip, deflate, br, or a list) returns verdict `unsupported`, a reason that says the body is encoded and NOT scanned, and 0 findings. v0.2.3 regressed against v0.2.2 here: a gzip response came back as verdict `unsupported` with no concealment findings and no reason saying the page was encoded, so a hidden payload that v0.2.2 caught went unreported. Nothing is decompressed (zip-bomb risk); the README "Honest scope" now says so.
- **Fix:** a never-ending encoded body is aborted early. The response is dropped as soon as the headers show a non-identity encoding, so `safe_fetch` does not wait for the body.
- Docs: the 198.18.0.0/15 carve-out (RFC 2544 range, allowed for fake-IP DNS setups) is documented in the README "Honest scope".
- Docs: a personal first name is removed from the docs.
- Repo: `tests/test-output.txt` is untracked and gitignored; the local file is kept.
- No package or manifest version change in this entry.

## 0.2.3 (2026-10-17)
- New Grok Bot template `grokbot-template/veilbreaker-guard.template.json` and its README, using the same key layout as the hermes-fleet-ops template (visibility, profile, memory, skills, routines, plugins, gettingStarted). It has a guard persona, 4 memory rules, and 11 plugin skills copied verbatim. Routines: a daily MCP pin check (`mcp_verify`) and a weekly self-test. Plugin: `veilbreaker`.
- New `getting-started` skill: install, connect, first scan.
- New `--cli selftest`: 18 built-in scan and egress fixtures. Prints pass/fail counts; exits 1 on any failure.
- New `tests/template.test.mjs`: the template parses and matches the reference layout, every skill exists in the plugin and is copied verbatim, every tool it names exists in `tools/list`, and the self-test passes.
- Version 0.2.3 in all manifests and the server.
- **Security: SSRF guard for `safe_fetch`.**
  - Covered: http(s) only; no credentials in URLs. Metadata and local hostnames are refused (metadata.google.internal, metadata, instance-data, localhost, `*.internal`, `*.local`, …).
  - All resolved addresses are checked, and the fetch is refused if any one is loopback (127/8, ::1), RFC1918, CGNAT 100.64/10, link-local or metadata (169.254/16, fe80::/10), ULA fc00::/7, 0.0.0.0/8, multicast, reserved, TEST-NETs, or the unspecified address. The same check applies to v4 addresses embedded in IPv6: IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible, NAT64 64:ff9b::/96 and 6to4. Odd IPv4 literals (hex, octal, integer, shortened) are normalised by the URL parser first.
  - Redirects are followed manually and every hop is re-checked, up to 5 hops.
  - Each request connects to the exact IP that passed the check (a custom `lookup` on node:http/https), so a DNS answer that changes after the check cannot redirect the request.
  - `allowHosts` is an exact host:port opt-in for tests only. It isn't exposed through MCP, the CLI or environment variables.
  - 198.18.0.0/15 is deliberately NOT blocked: some sandboxes, including this build box, answer DNS with fake IPs in that range.
  - Residual risks: when traffic goes through an outbound proxy or a fake-IP DNS layer, the guard validates the address the proxy hands out, not the real upstream one. Plain-http requests send Host/path to the validated IP only, but HTTPS certificate checks still use the hostname. IPv6 zone IDs are stripped.
- Tests: new `tests/ssrf.test.mjs` with 10 tests. The duplicate headline test is merged into one, and egress fixtures use user@example.com.
- README: "Measured results" now gives counts (1,634 of 2,242 and 797 of 2,242 within the 5,120-sample set) and names the 8 legitimate-use categories (8 × 40). One "Honest scope" line describes the SSRF guard.
- In-app test (2026-10-17, Grok Bot connector, Node v20.19.2): scan, safe_fetch, egress_check, mcp_pin and mcp_verify (unchanged and tampered) all PASS. egress_check ran on fake data after one approved Auto-review block; the metadata-URL safe_fetch was blocked by Auto-review and is covered by `tests/ssrf.test.mjs`. Details: [docs/IN-APP-TEST.md](docs/IN-APP-TEST.md).

## 0.2.2 (2026-10-17)
- Headline is now the same text in the README, the `ttp_catalog()` scope string and both plugin.json descriptions: "Deterministic, zero-dependency coverage of the latest documented (2025–2026) prompt-injection concealment and exfiltration TTPs. Built to pair with an ML classifier." The previous false-alarm claim is removed everywhere, and a test checks it stays out.
- README: new "Measured results" section (held-out benchmark, legitimate-use samples, and what `review` means on real pages).
- Version 0.2.2 in all manifests and the server.

## 0.2.1 (2026-10-17)
- README now says that every TTP finding carries a citation, and that operational notes (VB-I01 size cap, VB-I02 unsupported input) do not. VB-I01 findings now have `citation: null`.
- CATALOG gains VB-I01 and VB-I02 with `kind: "operational"`. Every entry now has a `kind` (`ttp`, `operational` or `design`). The README TTP table is generated from the catalog and a test checks they match exactly (id, kind, name, default severity, order).
- In `tests/ttp.test.mjs`, every benign look-alike also checks that there is no finding of that TTP at all, or that its maximum severity is none/low. The medium-and-above `has()` helper is unchanged.
- The README headline and the `ttp_catalog()` scope string are replaced with the exact new positioning line. Out-of-scope items move to a new `out_of_scope` field in `ttp_catalog()`. The word that previously led the positioning line is removed everywhere.
- Version 0.2.1 in `plugin.json`, `.cursor-plugin/plugin.json`, `package.json` and the server.

## 0.2.0 (2026-10-17)
- **CLI:** works through a symlinked entry point (`realpathSync` on both sides). It never exits 0 with empty output: errors print `{"error"}` JSON with exit 2 (usage/input) or 1 (internal). A missing file gives exit 2 with no stack trace. Input over the size cap returns `truncated: true` plus a VB-I01 finding. Binary or non-UTF-8 input returns verdict `unsupported` (VB-I02).
- **VB-T08 (key signal) reworked:** substantive text present only in a hidden or decoded view is `review`. It escalates to `suspicious` when agent-directed, judged by general grammar rules: an imperative addressed to an AI, about "the user", or carrying a URL/email target, or a second-person directive in CSS-hidden text. The phrase list is now only an extra signal. Descriptive alt/title/aria/meta text, machine data in attributes, and developer comments stay clean. `<noscript>` and `aria-hidden` content counts as visible.
- **New VB-T09, decode-and-follow wrappers:** high, verdict `suspicious`. New skill `decode-and-follow`.
- **VB-T02:** zero-width characters inside words above a density threshold are high. Stray ones are low. Emoji ZWJ and Arabic/Persian/Indic joiners stay exempt.
- **VB-T01:** TAG characters are high unless they form a valid emoji tag sequence (any emoji base + 1–32 tag digits/lowercase letters + CANCEL TAG).
- **VB-T03:** overrides and embeddings (LRO/RLO/LRE/RLE/PDF) are high. RLM/LRM and isolates are low in genuine RTL text and medium otherwise.
- **VB-T04:** any word mixing scripts is high (CJK scripts grouped; Common/Inherited ignored). Whole words in one non-Latin script are clean.
- **Decoding:** URL and entity decoding now targets encoded spans only, and HTML is decoded from text content rather than markup. This removes whole-page false positives found on real sites.
- **Verdicts:** low findings no longer raise the verdict to `review`.
- `egress_check`: the `enforce` mode is renamed `strict` (old name accepted), and the result field `enforcement` is renamed `handling`. The README no longer uses "full protection" or "enforced" wording.
- **README:** correct test command, `npm test`, a default-severity column in the TTP table, and split/multi-message payloads stated as out of scope.
- **New `package.json`:** private, zero dependencies, `npm test`.
- **Tests:** a new `tests/v02.test.mjs` with an attack and a benign look-alike per change, including a symlink test. The `has()` helper in `tests/ttp.test.mjs` now counts only medium-and-above findings as "flagged", because low notes are informational.


## 0.1.0 (2026-10-16)
- First release. Tools: `safe_fetch`, `reveal`, `scan`, `egress_check`, `mcp_pin`, `mcp_verify`, `ttp_catalog`.
- 12 skills: `step-0-untrusted-content` plus one per TTP family and a design-basis skill.
- 21 catalog entries; every citation verified by fetch on 2026-10-16.
- Tests: per-TTP attack/benign pairs, 12 blocked + 12 allowed egress flows, MCP pin/verify, safe_fetch fencing, CLI.
- Default egress mode: shadow (log-only).
