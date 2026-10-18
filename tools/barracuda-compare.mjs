#!/usr/bin/env node
// Reproduces the README "Barracuda October 2026" numbers.
//   node tools/barracuda-compare.mjs [--baseline <git-ref>] [--out <file>]
// Scans the 26 attack samples + control in tests/fixtures/barracuda/samples and the 1,120 legitimate-use samples in
// tests/fixtures/barracuda/benign-1120.json with this checkout's server, and (unless --baseline none) with the server at
// <git-ref> (default v0.3.0), then prints counts and every verdict difference. Read-only; no network.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const baseRef = arg("--baseline", "v0.3.0");
const outFile = arg("--out", null);
process.env.VEILBREAKER_LOG ??= path.join(os.tmpdir(), `vb-compare-${process.pid}.jsonl`);

const fx = path.join(root, "tests/fixtures/barracuda");
const samples = fs.readdirSync(path.join(fx, "samples")).sort().map((f) => ({ name: f, text: fs.readFileSync(path.join(fx, "samples", f), "utf8") }));
const attacks = samples.filter((s) => !s.name.startsWith("C0"));
const control = samples.filter((s) => s.name.startsWith("C0"));
const benign = JSON.parse(fs.readFileSync(path.join(fx, "benign-1120.json"), "utf8"));

const cur = await import(pathToFileURL(path.join(root, "server/index.mjs")).href);
let base = null, tmp = null;
if (baseRef !== "none") {
  const src = execFileSync("git", ["-C", root, "show", `${baseRef}:server/index.mjs`], { encoding: "utf8", maxBuffer: 64 << 20 });
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vb-base-"));
  fs.writeFileSync(path.join(tmp, "index.mjs"), src);
  base = await import(pathToFileURL(path.join(tmp, "index.mjs")).href);
}
const v = (mod, t) => mod.scan(t).verdict;
const lines = [];
const log = (s = "") => lines.push(s);
const count = (mod, set) => { const c = { clean: 0, review: 0, suspicious: 0 }; for (const s of set) c[v(mod, s.text)]++; return c; };
const fmt = (c, n) => `${c.review + c.suspicious} of ${n} flagged (${c.suspicious} suspicious, ${c.review} review, ${c.clean} clean)`;

log(`VeilBreaker Barracuda compare: current ${cur.VERSION ?? "(checkout)"}${base ? ` vs baseline ${baseRef}` : ""}`);
log(`Attack samples (${attacks.length}): current ${fmt(count(cur, attacks), attacks.length)}`);
if (base) log(`Attack samples (${attacks.length}): baseline ${fmt(count(base, attacks), attacks.length)}`);
log(`Control (${control.length}): current ${control.map((s) => `${s.name}=${v(cur, s.text)}`).join(", ")}`);
for (const set of ["tuning", "held-out", null]) {
  const sub = set ? benign.filter((b) => b.set === set) : benign;
  log(`Legitimate-use ${set ?? "all"} (${sub.length}): current ${fmt(count(cur, sub), sub.length)}${base ? `; baseline ${fmt(count(base, sub), sub.length)}` : ""}`);
}
if (base) {
  const diffs = [];
  for (const s of attacks) { const a = v(base, s.text), b = v(cur, s.text); if (a !== b) diffs.push(`attack ${s.name}: ${a} -> ${b}`); }
  benign.forEach((s, i) => { const a = v(base, s.text), b = v(cur, s.text); if (a !== b) diffs.push(`benign #${i} [${s.set}/${s.cat}]: ${a} -> ${b}`); });
  const bd = diffs.filter((d) => d.startsWith("benign")).length;
  log(`Legitimate-use verdicts that differ from ${baseRef}: ${bd} of ${benign.length}`);
  log(`Verdict differences (${diffs.length}):`);
  for (const d of diffs) log(`  ${d}`);
}
if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
const text = lines.join("\n") + "\n";
process.stdout.write(text);
if (outFile) fs.writeFileSync(outFile, text);
