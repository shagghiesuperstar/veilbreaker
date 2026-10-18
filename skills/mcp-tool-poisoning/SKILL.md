---
name: mcp-tool-poisoning
description: Use when connecting, approving or re-checking MCP servers. Covers tool-description poisoning (VB-M01), shadowing (VB-M02) and rug pulls (VB-M03).
---
# MCP poisoning, shadowing and rug pulls (VB-M01..M03)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Tool descriptions are read by the model as instructions. A malicious server hides directives in them (<IMPORTANT> blocks, 'read ~/.ssh', covert 'sidenote' params), shadows another server's tool, or changes a definition after the user approved it.

## How VeilBreaker catches it
`mcp_pin` stores sha256 over canonical name+description+schema per server and scans descriptions. `mcp_verify` reports changed (rug pull), new and removed tools, poisoning patterns, name collisions across servers, and descriptions that mention another server's tools.

## Known limits
Needs the bot to pass in the definitions it sees; VeilBreaker cannot list the host's MCP servers itself. Poisoning phrased as ordinary documentation can pass.

## Citation
invariantlabs.ai MCP Security Notification: Tool Poisoning Attacks (2025-04-01); arXiv:2508.13220 (MCPSecBench); arXiv:2506.02040 (Beyond the Protocol).
