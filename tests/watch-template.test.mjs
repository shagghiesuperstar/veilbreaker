import "./helpers/isolate-log.mjs";
// "VeilBreaker Watch" Grok Bot template: parses, same key layout as the guard template, skills verbatim, every named tool exists.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
import { handle, reveal, scan, egressCheck, mcpPin, mcpVerify, report, writeDashboard } from "../server/index.mjs";
const root = new URL("..", import.meta.url).pathname;
const file = path.join(root, "grokbot-template/veilbreaker-watch.template.json");
const guard = JSON.parse(fs.readFileSync(path.join(root, "grokbot-template/veilbreaker-guard.template.json"), "utf8"));
const load = () => JSON.parse(fs.readFileSync(file, "utf8"));
const keys = (arr) => [...new Set(arr.map((x) => JSON.stringify(Object.keys(x))))];

test("watch template parses and matches the guard template's key layout", () => {
  const t = load();
  assert.deepEqual(Object.keys(t), Object.keys(guard));
  assert.deepEqual(Object.keys(t.profile), Object.keys(guard.profile));
  assert.deepEqual(keys(t.memory), keys(guard.memory));
  assert.deepEqual(keys(t.skills), keys(guard.skills));
  assert.deepEqual(keys(t.routines), keys(guard.routines));
  assert.deepEqual(Object.keys(t.gettingStarted), Object.keys(guard.gettingStarted));
  assert.equal(t.profile.name, "VeilBreaker Watch");
  assert.match(t.profile.description, /Honest scope/); assert.match(t.profile.description, /cannot block host tools/);
  assert.equal(t.memory.length, 4); assert.equal(t.routines.length, 3);
  assert.deepEqual(t.plugins, ["veilbreaker"]);
});
test("watch template memories cover metadata-only log, report-only numbers, same-turn critical, local dashboard", () => {
  const m = load().memory.map((x) => x.content);
  assert.match(m[0], /metadata only/); assert.match(m[1], /only from the `report` tool/); assert.match(m[1], /Never estimate/);
  assert.match(m[2], /critical/i); assert.match(m[2], /same turn/); assert.match(m[3], /127\.0\.0\.1/); assert.match(m[3], /Never publish it to the internet/);
});
test("watch template routines: daily 08:00 digest (report since=24h), weekly dashboard (--cli dashboard --since 7d), daily mcp_verify", () => {
  const r = Object.fromEntries(load().routines.map((x) => [x.slug, x]));
  assert.equal(r["daily-veilbreaker-digest"].name, "VeilBreaker daily digest"); assert.match(r["daily-veilbreaker-digest"].description, /08:00/);
  assert.match(r["daily-veilbreaker-digest"].content, /`report` with since = 24h/); assert.match(r["daily-veilbreaker-digest"].content, /0 events/); assert.match(r["daily-veilbreaker-digest"].content, /top 3/);
  assert.equal(r["weekly-veilbreaker-dashboard"].name, "VeilBreaker dashboard"); assert.match(r["weekly-veilbreaker-dashboard"].content, /--cli dashboard --since 7d/); assert.match(r["weekly-veilbreaker-dashboard"].content, /Attach the HTML file in chat/);
  assert.equal(r["daily-mcp-pin-check"].name, "MCP pin check"); assert.match(r["daily-mcp-pin-check"].content, /`mcp_verify`/);
});
test("every watch template skill exists in the plugin and is copied verbatim; includes getting-started and watch-and-report", () => {
  const t = load();
  for (const n of ["getting-started", "watch-and-report"]) assert.ok(t.skills.some((s) => s.name === n), n);
  for (const s of t.skills) {
    const p = path.join(root, "skills", s.name, "SKILL.md");
    assert.ok(fs.existsSync(p), `missing plugin skill ${s.name}`);
    assert.equal(`---\nname: ${s.name}\ndescription: ${s.description}\n---\n${s.content}`, fs.readFileSync(p, "utf8"), s.name);
  }
  assert.ok(t.skills.some((s) => s.name === t.gettingStarted.skill));
  const gs = t.skills.find((s) => s.name === "getting-started").content;
  for (const step of [/Install/, /VEILBREAKER_MODE/, /`scan`/, /`report`/, /--cli dashboard/]) assert.match(gs, step);
});
test("every tool the watch template names exists in tools/list; CLI commands it names exist", async () => {
  const tools = new Set((await handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })).result.tools.map((x) => x.name));
  const text = fs.readFileSync(file, "utf8");
  const named = new Set([...text.matchAll(/`([a-z]+(?:_[a-z]+)+)`/g)].map((m) => m[1]));
  for (const m of text.matchAll(/`([a-z_]+)`/g)) if (tools.has(m[1])) named.add(m[1]);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-wt-"));
  const fields = new Set(); const walk = (o) => { if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) { fields.add(k); walk(v); } };
  [reveal("<p>a</p><!-- b -->"), scan("x"), egressCheck("url", { url: "https://a.example" }, {}), mcpPin([], { write: false }), mcpVerify([], { pins: {} }),
    report({ group_by: "ttp" }, { file: path.join(dir, "e.jsonl") }), writeDashboard({ out: path.join(dir, "d.html"), file: path.join(dir, "e.jsonl") })].forEach(walk);
  for (const f of fields) if (!tools.has(f)) named.delete(f);
  for (const n of named) assert.ok(tools.has(n), `template names unknown tool ${n}`);
  for (const r of ["report", "mcp_verify", "scan"]) assert.ok(named.has(r), r);
  for (const cmd of [...text.matchAll(/--cli ([a-z-]+)/g)].map((m) => m[1])) assert.ok(["dashboard", "serve-dashboard", "selftest", "report", "scan"].includes(cmd), cmd);
});
