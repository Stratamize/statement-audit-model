# Statement audit methodology and limitations

## Purpose

The Stratamize Statement Audit Model normalizes one processing statement into comparable monthly totals. It is designed for reproducible arithmetic, fee-taxonomy review, and month-over-month or provider-to-provider comparison. It is not a substitute for the original statement, merchant agreement, card-brand rules, tax advice, legal advice, an accounting opinion, or an interchange-qualification analysis.

## Procedure

1. Confirm that the source covers one USD statement period of no more than 62 inclusive days. If the statement combines currencies or inseparable periods, stop.
2. Record gross settled purchase volume and its matching settled purchase count. Do not use net deposits, net sales after refunds, authorization volume, or funding totals.
3. Identify every processing-related charge for the same period. Exclude transaction principal, refund and chargeback principal, reserves, withholding, loan or advance repayment, and equipment financing principal.
4. Assign each gross charge exactly once to the taxonomy in [`DATA_DICTIONARY.md`](./DATA_DICTIONARY.md). Put ambiguous processing charges in `other` with a note; do not drop them.
5. Sum the fee groups to `gross_processing_fees`. Record only processing-fee rebates or credits in `statement_credits`. Subtract those credits to obtain `total_processing_fees`.
6. Compute the effective rate from net processing fees and gross settled purchase volume. Compute average ticket from that same volume and count. Use decimal arithmetic and round half up only at the published precision.
7. Run the companion validator. Correct the source mapping—not the validator result—when a rule fails. Preserve the source statement privately according to the merchant’s controls; never attach it to this public resource.

## Equations

```text
gross_processing_fees = exact sum(fee_groups.amount)
total_processing_fees = gross_processing_fees - statement_credits
effective_rate = round_half_up(total_processing_fees / card_volume, 6)
average_ticket = round_half_up(card_volume / transaction_count, 2)
```

When volume and count are zero, `effective_rate` and `average_ticket` are `null`. Fixed monthly fees may still make `total_processing_fees` positive. A percentage shown to people is `effective_rate × 100`; the JSON value remains a decimal.

If a zero-activity statement also has zero processing fees, retain one explicit `other` fee group with amount `0.00`; schema v1.1.0 requires one fee-group entry and this convention avoids inventing a positive charge. CSV text cells beginning with `=`, `+`, `-`, or `@` (after leading whitespace) are rejected because spreadsheet software may interpret them as formulas.

## What the effective rate can and cannot show

The rate is an all-in normalization of the included statement costs. It can support consistent comparisons when records use the same basis. It does not isolate provider margin, prove that interchange was qualified correctly, predict a future bill, or guarantee savings. Card mix, ticket size, acceptance channel, rewards mix, disputes, seasonality, statement timing, and fee changes can move the rate without a pricing change.

Comparisons should use multiple representative statements when available and should present absolute dollars, volume, transaction count, fee groups, and rate together. A single rate without its basis and period is not a complete audit.

## Validation architecture

The JSON Schema enforces types, required fields, enums, bounds, and unknown-field rejection. The Python validator additionally enables date-format assertion, parses JSON numbers as `Decimal`, rejects duplicate keys and non-finite values, and enforces cross-field accounting rules. This split is intentional: Draft 2020-12 `format` is annotation by default, and JSON Schema does not express date ordering or arithmetic equality across fields.

Validation errors expose only rule code, JSON Pointer path, and a fixed message. They do not echo submitted values. The shipped corpus contains valid and deliberately invalid synthetic vectors so independent users can reproduce both acceptance and rejection behavior.

## Privacy and security boundary

This model needs statement-level aggregates only. It has no fields for PAN, truncated PAN, cardholder name, expiration date, track data, security codes, PIN/PIN block, bank account or routing numbers, tax or government identifiers, merchant owner data, credentials, tokens, or secrets. Unknown fields are rejected. Notes are scanned for Luhn-valid PAN-like sequences, labeled truncated-card references, authentication or bank data, email addresses, and common credential patterns. Unicode control characters that can hide or reorder displayed text are rejected.

Automated screening reduces accidental disclosure; it cannot prove that arbitrary prose contains no personal or confidential information. A human must review any record before public release. Never use this repository or a public dataset mirror to upload a real merchant statement or a record containing merchant-identifying information.

## Corrections and versioning

Published version artifacts and their checksums are immutable. A calculation or contract change receives a new semantic version, GitHub release, and Stratamize version identifier linked by the product identifier. Metadata-only corrections that do not change released files may be amended at the archive, but the repository documents the correction. Known limitations are disclosed rather than silently “fixed” in prior versions.
