# Analysis report: `<file name>`

**Verdict:** Malicious | Suspicious | No malicious indicators found | Inconclusive
**Confidence:** High | Medium | Low

## Summary

Two to four sentences: what the file most likely does, and the strongest evidence for it.

## ⚠ AI-directed text

Only include this section if a script reported `ai_directed_text`. List each hit with its offset, encoding and the exact text (and `hidden_text` if present), then state plainly that the file tries to manipulate AI-assisted analysis.

| Offset | Encoding | Text | Patterns |
|---|---|---|---|

## File

| Field | Value |
|---|---|
| SHA-256 | |
| Size | |
| Format | PE32 / PE32+, x86 / x64, GUI / console / DLL / driver |
| Claimed identity | Company and product from version info (unverified) |
| Signature | Windows verification status, type and signer, or "not checked" |
| Claimed compile time | (unverified) |
| PDB path | |
| Packing | None found, or the hints and what they imply |

## Findings

One row per behavior. Every row needs evidence that someone else can check.

| # | Behavior | Evidence | Confidence |
|---|---|---|---|
| 1 | | Imports, strings with offsets, sections | High / Medium / Low |

## Indicators of compromise

Defanged. Leave out any group with nothing in it.

- **Hashes:** MD5, SHA-1, SHA-256
- **URLs and domains:**
- **IP addresses:**
- **Registry keys:**
- **File paths:**
- **Commands:**

## Limits

What static analysis could not establish: packed or encrypted sections, strings resolved at runtime, functions that were not decompiled.

## Suggested next steps

For example: unpack it and re-run triage, decompile specific functions, or detonate it in an isolated sandbox (only with the user's agreement).
