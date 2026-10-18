// Grok Bot template: parses, matches the reference key layout, and every skill/tool it names exists in the plugin.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs"; import path from "node:path";
import { handle, selfTest, reveal, scan, egressCheck, mcpPin } from "../server/index.mjs";
const root = new URL("..", import.meta.url).pathname;
const file = path.join(root, "grokbot-template/veilbreaker-guard.template.json");

test("template JSON parses and uses the reference key layout", () => {
  const t = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(Object.keys(t), ["visibility", "profile", "memory", "skills", "routines", "plugins", "gettingStarted"]);
  assert.deepEqual(Object.keys(t.profile), ["name", "avatarColor", "avatarShape", "description"]);
  for (const m of t.memory) assert.deepEqual(Object.keys(m), ["kind", "createdAt", "content"]);
  for (const s of t.skills) assert.deepEqual(Object.keys(s), ["name", "description", "content"]);
  for (const r of t.routines) assert.deepEqual(Object.keys(r), ["slug", "name", "description", "content"]);
  assert.equal(t.memory.length, 4); assert.equal(t.routines.length, 2);
  assert.deepEqual(t.plugins, ["veilbreaker"]);
});
test("every skill in the template exists in the plugin and is copied verbatim (no new claims)", () => {
  const t = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(t.skills.some((s) => s.name === "step-0-untrusted-content"));
  for (const s of t.skills) {
    const p = path.join(root, "skills", s.name, "SKILL.md");
    assert.ok(fs.existsSync(p), `missing plugin skill ${s.name}`);
    assert.equal(`---\nname: ${s.name}\ndescription: ${s.description}\n---\n${s.content}`, fs.readFileSync(p, "utf8"), s.name);
  }
  assert.ok(t.skills.some((s) => s.name === t.gettingStarted.skill), "gettingStarted.skill must be one of the template skills");
});
test("every tool the template names exists in the plugin's tools/list", async () => {
  const tools = new Set((await handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })).result.tools.map((x) => x.name));
  const text = fs.readFileSync(file, "utf8");
  // candidates: backticked snake_case identifiers, plus the bare names of all real tools wherever backticked
  const named = new Set([...text.matchAll(/`([a-z]+(?:_[a-z]+)+)`/g)].map((m) => m[1]));
  for (const m of text.matchAll(/`([a-z_]+)`/g)) if (tools.has(m[1])) named.add(m[1]);
  // snake_case names that are result FIELDS (e.g. tag_payloads), not tools, are collected from real outputs and excluded
  const fields = new Set(); const walk = (o) => { if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) { fields.add(k); walk(v); } };
  [reveal("<p>a</p><!-- b -->"), scan("x"), egressCheck("url", { url: "https://a.example" }, {}), mcpPin([], { write: false })].forEach(walk);
  for (const f of fields) if (!tools.has(f)) named.delete(f);
  assert.ok(named.size >= 5, [...named].join(","));
  for (const n of named) assert.ok(tools.has(n), `template names unknown tool ${n}`);
  for (const r of ["mcp_verify"]) assert.ok(named.has(r));
});
test("CLI selftest command named by the weekly routine exists and passes", () => {
  const t = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.match(t.routines.find((r) => r.slug === "weekly-veilbreaker-self-test").content, /--cli selftest/);
  const r = selfTest(); assert.equal(r.failed, 0, JSON.stringify(r.results.filter((x) => !x.pass))); assert.ok(r.total >= 18);
});
