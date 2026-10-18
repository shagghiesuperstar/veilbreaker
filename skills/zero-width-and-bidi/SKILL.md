---
name: zero-width-and-bidi
description: Use when text contains invisible zero-width characters or bidi controls, or when scan reports VB-T02 / VB-T03.
---
# Zero-width and bidi tricks (VB-T02, VB-T03)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Zero-width characters split words so filters miss them, or encode bits as runs of invisible characters. Bidi overrides (U+202D/U+202E) make displayed text differ from the logical text the model reads.

## How VeilBreaker catches it
`reveal` strips them in the `normalized` view. `scan` ignores ZWJ inside emoji sequences, ZWNJ/ZWJ next to Arabic-script or Indic letters, a leading BOM, and LRM/RLM marks. Zero-width characters inside words above a density threshold (3+, or 1 per 20 words) or runs of 8+ are high; other stray ones are low. Overrides and embeddings (LRO/RLO/LRE/RLE/PDF) are high. RLM/LRM and isolates are low in genuine RTL text and medium without it.

## Known limits
Legitimate isolates inside Latin-only UI strings will show as medium. Whitespace-based steganography (trailing spaces, tabs) is not covered.

## Citation
arXiv:2504.11168.
