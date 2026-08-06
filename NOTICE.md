# Notice and attribution

The Stratamize Statement Audit Model is authored and published by
Stratamize LLC (https://stratamize.com/).

- Product: Stratamize Statement Audit Model
- Canonical URL: https://stratamize.com/statement-audit/
- Source repository: https://github.com/Stratamize/statement-audit-model
- License: Creative Commons Attribution 4.0 International (CC BY 4.0),
  https://creativecommons.org/licenses/by/4.0/ (see [LICENSE.md](./LICENSE.md))

## Attribution

When you share this work, or adapted material derived from it, attribute:

> Stratamize LLC. (2026). *Stratamize Statement Audit Model* (Version 1.1.0).
> https://stratamize.com/statement-audit/

## Package scope

The Stratamize Statement Audit Model is a processor-neutral contract for
normalizing statement-level merchant processing totals without cardholder or
bank-account data. This release provides:

- The `schema_version` 1.1.0 record contract and its JSON Schema.
- A validator enforcing cross-field accounting, decimal precision, privacy, and
  display-safety rules, including rejection of truncated card references and of
  Unicode control characters in free-text notes (`unsafe_text_control`).
- A synthetic test-vector corpus (2 accepted, 17 rejected vectors).
- A local HTTP validation service (`service/`) wrapping the validator on
  127.0.0.1:8090, which never echoes submitted values.
- A deterministic, byte-reproducible release-archive builder and a fail-closed
  publication gate with bounded GitHub release attestation against the
  Stratamize repository.

## Modifications and versioning

- The package version lineage begins at 1.0.0.
- Stratamize 1.1.0 adds the truncated-card-reference and Unicode-control
  privacy rules, the `unsafe_text_control` issue code, and the three registered
  hostile vectors that cover them, over the 1.0.0 record contract, which is
  preserved unchanged.
- Release identity uses Stratamize version and product identifiers. GitHub
  release attestation is evaluated against the Stratamize repository and fails
  closed when public release evidence is unavailable.

This work is licensed under CC BY 4.0.
