---
name: unicode-tag-smuggling
description: Use when content may hide ASCII in invisible Unicode TAG characters (U+E0000-E007F), or when scan reports VB-T01.
---
# Unicode TAG smuggling (VB-T01)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Each ASCII character is shifted into the invisible Unicode TAG block. Humans see nothing; tokenizers still see text, so a hidden instruction can ride along with harmless visible text and evade guardrail classifiers.

## How VeilBreaker catches it
`reveal` decodes TAG runs to visible ASCII (`tag_payloads`). `scan` flags any TAG characters (critical when the payload is instruction-like). TAG characters are high unless they form a valid emoji tag sequence (emoji base + 1–32 tag digits/lowercase letters + U+E007F CANCEL TAG, e.g. England/Scotland/Wales flags).

## Known limits
Only the TAG block is decoded here. Other invisible encodings are covered by zero-width and encoded-payload checks. Very short TAG runs inside unusual but legitimate emoji sequences may be reported.

## Citation
arXiv:2504.11168 (Bypassing LLM Guardrails: Unicode tags, zero-width and homoglyph character injection evade detectors).
