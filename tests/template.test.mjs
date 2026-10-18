import "./helpers/isolate-log.mjs";
// The single "VeilBreaker Guard & Watch" Grok Bot template (Guard and Watch combined in 0.3.1): parses, matches the reference key layout,
// skills are copied verbatim from the plugin, every tool and CLI command it names exists, and the self-test passes.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { handle, selfTest, reveal, scan, egressCheck, mcpPin, mcpVerify, report, writeDashboard } from "../server/index.mjs";
const root = new URL("..", import.meta.url).pathname;
const file = path.join(root, "grokbot-template/veilbreaker.template.json");
const load = () => JSON.parse(fs.readFileSync(file, "utf8"));

test("exactly one template ships: veilbreaker.template.json (the old guard and watch files are gone)", () => {
  assert.deepEqual(fs.readdirSync(path.join(root, "grokbot-template")).filter((f) => f.endsWith(".template.json")), ["veilbreaker.template.json"]);
});
test("template JSON parses and uses the reference key layout", () => {
  const t = load();
  assert.deepEqual(Object.keys(t), ["visibility", "profile", "memory", "skills", "routines", "plugins", "gettingStarted"]);
  assert.deepEqual(Object.keys(t.profile), ["name", "avatarColor", "avatarShape", "description"]);
  for (const m of t.memory) assert.deepEqual(Object.keys(m), ["kind", "createdAt", "content"]);
  for (const s of t.skills) assert.deepEqual(Object.keys(s), ["name", "description", "content"]);
  for (const r of t.routines) assert.deepEqual(Object.keys(r), ["slug", "name", "description", "content"]);
  assert.equal(t.profile.name, "VeilBreaker Guard & Watch");
  assert.match(t.profile.description, /Honest scope/); assert.match(t.profile.description, /cannot block host tools/);
  assert.equal(t.memory.length, 8); assert.equal(t.routines.length, 4);
  assert.deepEqual(t.plugins, ["veilbreaker"]);
});
test("memories cover in-flight routing, hidden-only, egress, pins, metadata-only log, report-only numbers, same-turn critical, local dashboard", () => {
  const m = load().memory.map((x) => x.content);
  assert.match(m[0], /`safe_fetch`/); assert.match(m[1], /hidden or decoded/); assert.match(m[2], /`egress_check`/); assert.match(m[3], /`mcp_pin`/);
  assert.match(m[4], /metadata only/); assert.match(m[5], /only from the `report` tool/); assert.match(m[5], /Never estimate/);
  assert.match(m[6], /critical/i); assert.match(m[6], /same turn/); assert.match(m[7], /127\.0\.0\.1/); assert.match(m[7], /Never publish it to the internet/);
});
test("routines: daily 08:00 digest (report since=24h), weekly dashboard (--cli dashboard --since 7d), daily mcp_verify, weekly self-test", () => {
  const r = Object.fromEntries(load().routines.map((x) => [x.slug, x]));
  assert.equal(r["daily-veilbreaker-digest"].name, "VeilBreaker daily digest"); assert.match(r["daily-veilbreaker-digest"].description, /08:00/);
  assert.match(r["daily-veilbreaker-digest"].content, /`report` with since = 24h/); assert.match(r["daily-veilbreaker-digest"].content, /0 events/); assert.match(r["daily-veilbreaker-digest"].content, /top 3/);
  assert.equal(r["weekly-veilbreaker-dashboard"].name, "VeilBreaker dashboard"); assert.match(r["weekly-veilbreaker-dashboard"].content, /--cli dashboard --since 7d/); assert.match(r["weekly-veilbreaker-dashboard"].content, /Attach the HTML file in chat/);
  assert.equal(r["daily-mcp-pin-check"].name, "MCP pin check"); assert.match(r["daily-mcp-pin-check"].content, /`mcp_verify`/);
  assert.equal(r["weekly-veilbreaker-self-test"].name, "VeilBreaker self-test"); assert.match(r["weekly-veilbreaker-self-test"].content, /--cli selftest/);
});
test("every skill in the template exists in the plugin and is copied verbatim (no new claims)", () => {
  const t = load();
  for (const n of ["getting-started", "step-0-untrusted-content", "watch-and-report", "mcp-tool-poisoning"]) assert.ok(t.skills.some((s) => s.name === n), n);
  assert.equal(new Set(t.skills.map((s) => s.name)).size, t.skills.length, "no duplicate skills");
  for (const s of t.skills) {
    const p = path.join(root, "skills", s.name, "SKILL.md");
    assert.ok(fs.existsSync(p), `missing plugin skill ${s.name}`);
    assert.equal(`---\nname: ${s.name}\ndescription: ${s.description}\n---\n${s.content}`, fs.readFileSync(p, "utf8"), s.name);
  }
  assert.ok(t.skills.some((s) => s.name === t.gettingStarted.skill), "gettingStarted.skill must be one of the template skills");
  const gs = t.skills.find((s) => s.name === "getting-started").content;
  for (const step of [/Install/, /VEILBREAKER_MODE/, /`scan`/, /`report`/, /--cli dashboard/]) assert.match(gs, step);
});
test("every tool the template names exists in tools/list, all 8 are named, and every CLI command it names exists", async () => {
  const tools = new Set((await handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })).result.tools.map((x) => x.name));
  const text = fs.readFileSync(file, "utf8");
  // candidates: backticked snake_case identifiers, plus the bare names of all real tools wherever backticked
  const named = new Set([...text.matchAll(/`([a-z]+(?:_[a-z]+)+)`/g)].map((m) => m[1]));
  for (const m of text.matchAll(/`([a-z_]+)`/g)) if (tools.has(m[1])) named.add(m[1]);
  // snake_case names that are result FIELDS (e.g. tag_payloads), not tools, are collected from real outputs and excluded
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-t-"));
  const fields = new Set(); const walk = (o) => { if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) { fields.add(k); walk(v); } };
  [reveal("<p>a</p><!-- b -->"), scan("x"), egressCheck("url", { url: "https://a.example" }, {}), mcpPin([], { write: false }), mcpVerify([], { pins: {} }),
    report({ group_by: "ttp" }, { file: path.join(dir, "e.jsonl") }), writeDashboard({ out: path.join(dir, "d.html"), file: path.join(dir, "e.jsonl") })].forEach(walk);
  for (const f of fields) if (!tools.has(f)) named.delete(f);
  for (const n of named) assert.ok(tools.has(n), `template names unknown tool ${n}`);
  for (const r of ["scan", "safe_fetch", "egress_check", "mcp_pin", "mcp_verify", "reveal", "report", "ttp_catalog"]) assert.ok(named.has(r), r);
  for (const cmd of [...text.matchAll(/--cli ([a-z-]+)/g)].map((m) => m[1])) assert.ok(["dashboard", "serve-dashboard", "selftest", "report", "scan"].includes(cmd), cmd);
});
test("CLI selftest command named by the weekly routine exists and passes", () => {
  const r = selfTest(); assert.equal(r.failed, 0, JSON.stringify(r.results.filter((x) => !x.pass))); assert.ok(r.total >= 18);
});
