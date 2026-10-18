---
name: encoded-payloads
description: Use when content contains base64, hex, rot13, percent-encoded or HTML-entity blobs, or when scan reports VB-T05.
---
# Encoded payloads (VB-T05)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Instructions are hidden in encodings that the model can decode on its own but filters do not read.

## How VeilBreaker catches it
`reveal` decodes base64/base64url, hex and \\x escapes, percent-encoding, HTML entities and rot13, up to depth 2, capped at 64 KB decoded and 64 candidates per layer. `scan` flags decodes that contain instruction-like text or chat-template tokens. `data:font|audio|video;base64` payloads and binary decodes (hashes) are ignored. `data:image` base64 is decoded and checked (Barracuda, October 2026: instructions hidden in an image data string): it is flagged when the bytes don't match the declared image type and read as text, or when readable text inside the bytes is addressed to an AI. Real PNG, GIF, JPEG and SVG images with normal metadata stay clean. `reveal` lists each one under `data_images` (declared type, size, magic check).

## Known limits
Other ciphers, compression, and multi-layer chains deeper than 2 are not decoded. Decoded text that is benign is not reported. Only the first 16 data:image strings and 256 KB of base64 each are decoded; text hidden by steganography in pixel values is not.

## Citation
arXiv:2504.11168 (encoding-based evasion); arXiv:2302.12173; Barracuda Threat Spotlight, 2026-10-07.
