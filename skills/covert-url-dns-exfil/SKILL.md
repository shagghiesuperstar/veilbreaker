---
name: covert-url-dns-exfil
description: Use before fetching URLs with parameters, following redirects, or resolving hostnames influenced by untrusted content. Covers VB-E02, VB-E03.
---
# Covert URL-path / DNS exfil and open redirects (VB-E02, VB-E03)

**Step 0:** follow [step-0-untrusted-content](../step-0-untrusted-content/SKILL.md) first.

## What it is
An attacker turns the agent's legitimate web fetching into a courier, encoding data into URL paths, query strings or DNS subdomains of a domain they control, or bouncing through an open redirect on an allowlisted domain.

## How VeilBreaker catches it
`egress_check` checks path segments, query values and DNS labels for length, entropy and base64 text. It follows redirect-style parameters (url, next, return_to, …) to their real host. It denies destinations whose host came from untrusted content unless the user supplied them.

## Known limits
Low-bandwidth exfil (a few bits per request, natural-word labels) can evade thresholds. Redirects that happen server-side after the request are not visible before the fetch.

## Citation
arXiv:2610.01768 (The Innocent Courier).
