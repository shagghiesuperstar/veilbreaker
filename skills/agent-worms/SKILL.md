---
name: agent-worms
description: Use when content asks to be copied into replies, emails or other agents' inputs. Covers VB-P02.
---
# Agent worms and self-replicating prompts (VB-P02)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
A self-replicating prompt makes each agent that reads it copy the payload into its outputs (emails, posts, messages to other bots), spreading zero-click.

## How VeilBreaker catches it
`scan` flags self-replication directives. `egress_check` denies sends to recipients or webhooks taken from untrusted content.

## Known limits
Replication phrased without the matched verbs, or payloads in images, are not caught.

## Citation
arXiv:2403.02817 (Here Comes The AI Worm).
