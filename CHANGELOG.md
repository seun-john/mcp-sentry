# Changelog

## Unreleased

- `HIDDEN_TEXT` no longer fires on a zero-width joiner or non-joiner that sits between two letters of the same joining script (Persian and other Arabic-script text, Indic scripts, Thai, Khmer, Myanmar) or inside an emoji sequence. Joiners next to Latin text, at the edges of a string, and every other invisible character are still reported.
- `scan` accepts `approved_definitions`; a `CHANGED` finding then lists what changed (`added`, `removed`, `extended` with the appended text, `edited` with before and after). Status and strict-mode behaviour are unchanged.

## 0.1.0

First release.

- `scan`: fingerprint tool definitions, compare with an approved baseline, flag instruction-shaped or hidden text in descriptions and schemas, and decide ALLOW or BLOCK for recorded calls against an explicit policy.
- `baseline`: write the approved fingerprints for a tool list.
- `access`: turn a declared permission inventory into plain-language capabilities and flag broad or high-impact ones.
