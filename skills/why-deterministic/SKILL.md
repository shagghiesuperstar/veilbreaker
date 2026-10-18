---
name: why-deterministic
description: Use when asked why VeilBreaker uses no model, what it does not cover, or how egress_check relates to CaMeL/FIDES/Progent.
---
# Design basis: deterministic checks and capability control

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Adaptive attacks (RL-trained, architecture-aware) beat learned prompt-injection detectors. Capability and information-flow designs (CaMeL, FIDES, Progent) limit what tainted data can do instead of trying to recognise it.

## How VeilBreaker catches it
Every VeilBreaker decision is a fixed rule with a cited TTP, so results are reproducible and benchmarkable (`node server/index.mjs --cli scan <file>`). `egress_check` is a lightweight, deterministic approximation of taint/capability checks at the egress point.

## Known limits
VeilBreaker does not stop reworded or semantic attacks and is not a full CaMeL/FIDES/Progent implementation. It cannot block host built-in tools; in the default shadow mode a deny is recorded to the metadata-only event log and reported to the user, and the bot has to stop the action.

## Citation
arXiv:2602.05746; arXiv:2507.07417; arXiv:2606.15057 (adaptive attacks); arXiv:2503.18813 (CaMeL); arXiv:2505.23643 (FIDES); arXiv:2504.11703 (Progent).
