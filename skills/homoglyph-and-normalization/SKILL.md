---
name: homoglyph-and-normalization
description: Use when words mix Latin with Cyrillic/Greek letters or use fullwidth/compatibility characters, or when scan reports VB-T04.
---
# Homoglyphs and NFKC tricks (VB-T04)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Look-alike letters from other scripts (Cyrillic а, р, о) or fullwidth forms make text look normal to humans while dodging keyword filters, or impersonate brands and domains.

## How VeilBreaker catches it
`scan` flags (high) any word whose letters come from more than one script (Latin, Cyrillic, Greek, Armenian, Georgian, Cherokee, Hebrew, Arabic, … ; Han/Kana/Hangul count as one CJK group), and instruction text that only appears after NFKC normalization. `egress_check` flags punycode/IDN hosts.

## Known limits
Single-script confusables (an all-Cyrillic word that looks Latin) are not flagged. Whole words in one non-Latin script, Japanese mixed kana/kanji, and accented Latin are clean.

## Citation
arXiv:2504.11168.
