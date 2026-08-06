# Payment statement audit data dictionary

This dictionary defines v1.1.0 of the Stratamize Statement Audit Model record contract. Words such as “volume,” “fees,” and “transactions” are ambiguous across provider statements; the definitions below are part of the contract, not suggestions.

## Record-level fields

| Field | Type | Required | Definition |
|---|---:|:---:|---|
| `schema_version` | string | yes | Literal `1.1.0`. A different value requires a different schema and validator. |
| `calculation_basis` | string | yes | Literal `gross_settled_purchase_volume_and_net_processing_fees`. It prevents unlike numerator and denominator conventions from being compared silently. |
| `statement_period.start` | ISO date | yes | First calendar date represented by the statement, inclusive. |
| `statement_period.end` | ISO date | yes | Last calendar date represented by the statement, inclusive. It must be on or after `start`; the inclusive period may not exceed 62 days. |
| `currency` | string | yes | Literal `USD`. Do not convert or combine other currencies in a v1.1.0 record. |
| `card_volume` | USD | yes | Gross dollar amount of settled purchase transactions in the period. Include the full settled purchase amount, including tax and tip when those are part of the capture. Exclude declines, authorization-only events, voids, refunds, chargebacks, cash advances, reserves, and funding adjustments. |
| `transaction_count` | integer | yes | Number of settled purchase transactions included in `card_volume`. Exclude declines, authorization-only events, voids, refunds, and chargebacks. Volume and count must both be zero or both be positive. |
| `gross_processing_fees` | USD | yes | Sum of the nine `fee_groups` before processing-fee credits. It includes only fees for accepting, authorizing, settling, supporting, or administering card processing. |
| `statement_credits` | USD | yes | Processing-fee credits or rebates applied on the statement. Exclude customer refunds, chargeback principal, reserve releases, deposit adjustments, and other movement of merchant funds. |
| `total_processing_fees` | USD | yes | Net fee numerator: `gross_processing_fees - statement_credits`. It cannot be negative in v1.1.0. |
| `effective_rate` | decimal or null | yes | `total_processing_fees / card_volume`, rounded half up to six decimal places. Store `2.2918%` as `0.022918`. It must be `null` when `card_volume` is zero. |
| `average_ticket` | USD or null | yes | `card_volume / transaction_count`, rounded half up to cents. It must be `null` when `transaction_count` is zero. |
| `pricing_model` | enum | yes | How pricing is presented on the source statement: `interchange_plus`, `flat_rate`, `tiered`, `subscription`, `dual_pricing`, or `unknown`. This is not an interchange-qualification opinion. |
| `fee_groups` | array | yes | One entry per used category. Categories are unique, amounts are gross nonnegative charges, and their exact cent sum equals `gross_processing_fees`. For a zero-activity, zero-fee statement, use one `other` entry with amount `0.00` because schema v1.1.0 requires at least one group. |
| `review_notes` | string array | no | Short explanations of classification decisions. Never put merchant identity, card/account data, credentials, or secrets here. |

All USD fields permit at most two decimal places. Rates permit at most six decimal places. Numbers must be finite. The validator imposes high operational ceilings to reject account-number-shaped or clearly implausible input; those ceilings are data-safety bounds, not merchant eligibility limits.

## Fee-group taxonomy

| Category | Include | Exclude or redirect |
|---|---|---|
| `interchange` | Issuer/interchange charges presented by the statement | Network assessments and provider markup |
| `assessments` | Card-network assessment, access, and brand charges | Interchange and processor markup |
| `processor_markup` | Provider percentage, basis-point, per-item, or service markup not assigned elsewhere | Pass-through interchange and assessments |
| `authorization` | Authorization, gateway, capture, AVS, and similar per-attempt service fees | Settled-item markup already classified in `processor_markup` |
| `monthly` | Monthly account, statement, minimum, batch, or platform administration fees | Equipment service and PCI program fees when separately stated |
| `pci` | PCI program, non-validation, or compliance-service fees | Penalties unrelated to processing, which belong in `other` with a note |
| `equipment` | Terminal rental, device service, replacement plan, or connectivity fees charged on the processing statement | Equipment sale principal, financing, or lease obligations outside processing cost |
| `chargebacks` | Chargeback, retrieval, arbitration, and dispute administration fees | Chargeback transaction principal or lost sale amount |
| `other` | A processing-related fee that fits no category, with a concise classification note | Refund principal, reserves, taxes withheld, loans/advances, financing principal, or merchant deposits |

Never omit a fee to make a rate look better. If the source statement does not provide enough information to classify a processing-related charge, put it in `other` and document the reason. If the statement mixes periods or currencies and they cannot be separated faithfully, do not publish a v1.1.0 record.
