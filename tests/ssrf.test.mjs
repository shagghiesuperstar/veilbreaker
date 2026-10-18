import "./helpers/isolate-log.mjs";
// SSRF guard for safe_fetch: address checks on every resolved IP, manual redirects re-checked per hop, hop cap.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { safeFetch, checkUrl, ipBlocked } from "../server/index.mjs";

const PUBLIC = async () => [{ address: "93.184.215.14", family: 4 }];
function server(handler) { return new Promise((res) => { const s = http.createServer(handler); s.listen(0, "127.0.0.1", () => res(s)); }); }

test("SSRF: direct cloud-metadata IP is rejected", async () => {
  await assert.rejects(safeFetch("http://169.254.169.254/latest/meta-data/"), /blocked: .*169\.254\.169\.254/);
  await assert.rejects(safeFetch("http://[::ffff:169.254.169.254]/"), /blocked/);
  await assert.rejects(safeFetch("http://[fd00:ec2::254]/"), /blocked/);
});
test("SSRF: metadata hostnames are rejected without resolving", async () => {
  for (const u of ["http://metadata.google.internal/computeMetadata/v1/", "http://metadata/", "http://instance-data/latest/", "http://localhost:8080/", "http://foo.localhost/"])
    await assert.rejects(checkUrl(u, { lookupImpl: PUBLIC }), /blocked: hostname/, u);
});
test("SSRF: public-looking URL that 302s to 169.254.169.254 is rejected (allowlist covers first hop only)", async () => {
  let hits = 0;
  const s = await server((q, r) => { hits++; r.writeHead(302, { Location: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }); r.end(); });
  try {
    await assert.rejects(safeFetch(`http://127.0.0.1:${s.address().port}/innocent`, { allowHosts: [`127.0.0.1:${s.address().port}`] }), /blocked: .*169\.254\.169\.254/);
    assert.equal(hits, 1, "first hop was fetched, second hop was refused before connecting");
  } finally { s.close(); }
});
test("SSRF: redirect to a private / mapped / non-allowlisted loopback address is rejected", async () => {
  for (const loc of ["http://10.0.0.7/admin", "http://[::ffff:127.0.0.1]:9/", "http://127.0.0.1:1/", "http://0x7f000001/", "http://metadata.google.internal/"]) {
    const s = await server((q, r) => { r.writeHead(307, { Location: loc }); r.end(); });
    try { await assert.rejects(safeFetch(`http://127.0.0.1:${s.address().port}/`, { allowHosts: [`127.0.0.1:${s.address().port}`] }), /blocked/, loc); }
    finally { s.close(); }
  }
});
test("SSRF: private IPs and odd literal forms are rejected", async () => {
  for (const u of ["http://10.0.0.5/", "http://172.16.0.1/", "http://172.31.255.254/", "http://192.168.1.1/", "http://127.0.0.1/", "http://127.1/", "http://0x7f000001/",
    "http://2130706433/", "http://017700000001/", "http://0.0.0.0/", "http://0/", "http://[::1]/", "http://[::]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/",
    "http://[fe80::1]/", "http://[fc00::1]/", "http://[fd12:3456::1]/", "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::]/", "http://100.100.100.100/"])
    await assert.rejects(checkUrl(u), /blocked/, u);
});
test("SSRF: EVERY resolved address is checked, not just the first", async () => {
  await assert.rejects(checkUrl("https://looks-public.example/", { lookupImpl: async () => [{ address: "93.184.215.14", family: 4 }, { address: "10.0.0.1", family: 4 }] }), /10\.0\.0\.1/);
  await assert.rejects(checkUrl("https://looks-public.example/", { lookupImpl: async () => [{ address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 }, { address: "::ffff:169.254.169.254", family: 6 }] }), /169\.254/);
});
test("SSRF: redirect hops are capped", async () => {
  const s = await server((q, r) => { r.writeHead(302, { Location: "/again" }); r.end(); });
  try { await assert.rejects(safeFetch(`http://127.0.0.1:${s.address().port}/`, { allowHosts: [`127.0.0.1:${s.address().port}`], maxHops: 3 }), /more than 3 redirects/); }
  finally { s.close(); }
});
test("SSRF: credentials-in-URL and non-http schemes are rejected", async () => {
  await assert.rejects(checkUrl("https://user:pass@example.com/", { lookupImpl: PUBLIC }), /credentials/);
  for (const u of ["file:///etc/passwd", "gopher://127.0.0.1:6379/_x", "ftp://example.com/"]) await assert.rejects(checkUrl(u), /only http/);
});
test("SSRF: a normal public host is allowed (deterministic resolver)", async () => {
  const r = await checkUrl("https://example.com/", { lookupImpl: PUBLIC });
  assert.equal(r.address, "93.184.215.14");
  for (const ip of ["93.184.215.14", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) assert.equal(ipBlocked(ip), null, ip);
});
test("SSRF: a normal page is fetched (loopback allowlisted fixture; no external network)", async () => {
  const s = await server((q, r) => { r.writeHead(200, { "Content-Type": "text/html" }); r.end("<html><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>"); });
  try {
    const r = await safeFetch(`http://127.0.0.1:${s.address().port}/`, { allowHosts: [`127.0.0.1:${s.address().port}`], timeoutMs: 10000 });
    assert.equal(r.status, 200); assert.equal(r.verdict, "clean"); assert.equal(r.hops.length, 1);
  } finally { s.close(); }
});
