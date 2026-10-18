import "./helpers/isolate-log.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs"; import path from "node:path";
const root = new URL("..", import.meta.url).pathname;
for (const d of fs.readdirSync(path.join(root, "skills"))) test(`skill ${d}: frontmatter, step-0 ref, citation`, () => {
  const s = fs.readFileSync(path.join(root, "skills", d, "SKILL.md"), "utf8");
  assert.match(s, /^---\nname: [\w-]+\ndescription: /);
  if (d !== "step-0-untrusted-content") { assert.match(s, /step-0-untrusted-content/); assert.match(s, /(arXiv|CVE|invariantlabs)/); assert.match(s, /## Known limits/); }
});
test("README states honest scope", () => {
  const r = fs.readFileSync(path.join(root, "README.md"), "utf8");
  assert.match(r, /does not stop every prompt injection/i); assert.doesNotMatch(r, /full protection|enforced/i); assert.match(r, /npm test/); assert.match(r, /split|multi-message/i); assert.match(r, /out of scope/i); assert.match(r, /strongest when reads go through `safe_fetch`/i);
});
