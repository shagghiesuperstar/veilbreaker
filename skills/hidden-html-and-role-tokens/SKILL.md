---
name: hidden-html-and-role-tokens
description: Use for web pages and HTML email: hidden text, comments, alt/aria/meta, and chat-template role tokens. Covers scan VB-T06, VB-T07 and the key signal VB-T08.
---
# Hidden HTML, role tokens and the key signal (VB-T06/T07/T08)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
Indirect prompt injection plants instructions in content the agent reads but the human does not see: HTML comments, display:none, visibility:hidden, zero font size, off-screen or white-on-white text, alt/title/aria/meta attributes, or fake <|im_start|>system turns.

## How VeilBreaker catches it
`reveal` splits HTML into visible and hidden text. `scan` flags instruction-like hidden text (VB-T07), role tokens (VB-T06), and the **key signal** VB-T08: substantive text that appears only in a hidden or decoded view is `review`; it becomes `suspicious` when it is agent-directed (an imperative addressed to an AI, about "the user", carrying a URL/email target, or a second-person directive in CSS-hidden text). Descriptive alt/title/aria/meta text and developer comments stay clean; the phrase list is only an extra signal. `<noscript>` and `aria-hidden` content is treated as visible. `safe_fetch` puts hidden material in a labelled section inside the UNTRUSTED fence.

## Known limits
CSS from external stylesheets and JavaScript-rendered content are not evaluated (regex tokenizer, no browser). White-on-white is best effort (inline styles only). Visible-text injections that are reworded are out of scope.

## Citation
arXiv:2302.12173 (Indirect Prompt Injection).
