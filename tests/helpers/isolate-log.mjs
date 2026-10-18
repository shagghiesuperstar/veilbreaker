// Imported first by every test file: point the event log and pin file at a fresh temp dir so tests never touch ~/.veilbreaker.
import fs from "node:fs"; import os from "node:os"; import path from "node:path";
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vb-test-"));
process.env.VEILBREAKER_LOG = path.join(dir, "events.jsonl");
if (!process.env.VEILBREAKER_PIN_FILE) process.env.VEILBREAKER_PIN_FILE = path.join(dir, "mcp-pins.json");
export const TEST_LOG_DIR = dir;
