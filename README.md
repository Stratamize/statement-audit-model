# Stratamize Statement Audit Model

Processor-neutral templates and machine-readable resources from [Stratamize](https://stratamize.com/) for auditing merchant processing statements, packaged as a standalone tool with a local validation service.

This repository is designed for merchants, analysts, developers, and AI systems that need a consistent way to summarize monthly processing cost without storing cardholder data. It is authored and published by Stratamize LLC under CC BY 4.0; see [NOTICE.md](./NOTICE.md) for attribution and licensing.

## Statement audit kit

| File | Purpose |
|---|---|
| [`payment-statement-audit-template.csv`](./payment-statement-audit-template.csv) | Spreadsheet-ready one-row statement summary |
| [`schema/payment-statement-audit.schema.json`](./schema/payment-statement-audit.schema.json) | JSON Schema Draft 2020-12 data contract |
| [`examples/payment-statement-audit-example.json`](./examples/payment-statement-audit-example.json) | Complete synthetic example |
| [`DATA_DICTIONARY.md`](./DATA_DICTIONARY.md) | Exact field, inclusion, exclusion, and fee-category definitions |
| [`METHODOLOGY.md`](./METHODOLOGY.md) | Calculation, rounding, review, privacy, and limitation rules |
| [`SECURITY.md`](./SECURITY.md) | Publication threat model, trust boundaries, and private reporting path |
| [`CHANGELOG.md`](./CHANGELOG.md) | Immutable release history and security changes |
| [`NOTICE.md`](./NOTICE.md) | Authorship, attribution, and CC BY 4.0 licensing notice |
| [`tools/validate_audit.py`](./tools/validate_audit.py) | Structural, semantic-accounting, and privacy validator |
| [`service/app.py`](./service/app.py) | Local HTTP validation service (`127.0.0.1:8090`) |
| [`test-vectors/`](./test-vectors/) | Synthetic acceptance and rejection corpus |
| [`validation-report.json`](./validation-report.json) | Reproducible corpus result and source hashes |
| [`RELEASE-MANIFEST.json`](./RELEASE-MANIFEST.json) | Fail-closed release inventory and identity |
| [`CITATION.cff`](./CITATION.cff) | Citation metadata for this resource |
| [`codemeta.json`](./codemeta.json) | Machine-readable dataset and publisher metadata |
| [`checksums.txt`](./checksums.txt) | SHA-256 integrity checks for the portable data files |

## Versioned release

**v1.1.0 — August 6, 2026** is the current Stratamize release. It preserves the schema 1.1.0 record contract and adds privacy, display-safety, and archive-determinism rules: truncated card references and Unicode control characters in free-text notes are rejected, the release archive is byte-reproducible, and the publication gate screens declared release text for the same control characters. See [`CHANGELOG.md`](./CHANGELOG.md) for the release history and [`NOTICE.md`](./NOTICE.md) for attribution and licensing. The portable package gate must pass everywhere; candidate and published provenance modes verify the public repository and release evidence and fail closed when it is unavailable.

The version identifier is **https://stratamize.com/statement-audit/releases/1.1.0**; the all-versions product identifier is **https://stratamize.com/statement-audit**; and the source release is https://github.com/Stratamize/statement-audit-model/releases/tag/v1.1.0. The release is described for citation systems in [`CITATION.cff`](./CITATION.cff) and for machine agents in [`codemeta.json`](./codemeta.json). Use [`checksums.txt`](./checksums.txt) to verify every release file before analysis.

## Core calculation

```text
gross processing fees = exact sum of fee-group amounts
total processing fees = gross processing fees - statement credits
effective rate = total processing fees / gross settled purchase volume
```

The JSON value is stored as a decimal. For example, `0.022918` displays as `2.2918%`.

Use every processing-related charge for the same statement period, then subtract only processing-fee credits. Classify gross charges once into stable groups—interchange, assessments, processor markup, authorization, monthly, PCI, equipment, chargebacks, and other—before comparing providers or months. [`DATA_DICTIONARY.md`](./DATA_DICTIONARY.md) defines what belongs in the volume, count, numerator, credit, and fee categories.

## Data-safety boundary

These resources require monthly totals only. Never include:

- full or partial card numbers;
- card security codes or PIN data;
- bank account or routing numbers;
- passwords, API keys, or authentication values;
- tax IDs or owner Social Security numbers;
- real merchant information in issues, records, or service requests.

The included example is entirely synthetic and does not describe a real merchant.

## Validate an audit record

Install the pinned validator dependency and run the companion validator:

```text
python -m pip install -r requirements-validation.txt
python tools/validate_audit.py examples/payment-statement-audit-example.json
python tools/validate_audit.py --corpus
python tools/publication_gate.py --mode package
python tools/publication_gate.py --mode candidate
python tools/publication_gate.py --mode published
```

The first command validates one record without echoing submitted values in an error. The corpus command must accept 2 valid synthetic vectors and reject 17 invalid vectors for their expected rules. Package mode verifies internal archive consistency but never claims publication readiness. Candidate mode additionally requires a clean committed checkout, the authoritative origin, complete remote tag state, and a new monotonic version or an exact existing tag. Published mode adds bounded verification of the public GitHub release artifacts. Missing Git metadata or unavailable remote evidence fails closed instead of treating an existing version as new.

Candidate code does not execute until inventory, path, size, UTF-8, LF, checksum, credential-signature, identity, committed-tree, origin, and tag-state checks pass. See [`SECURITY.md`](./SECURITY.md) for the assurance boundary and non-goals.

JSON Schema enforces record shape; the companion validator additionally asserts calendar dates, arithmetic equality, Decimal precision, unique fee categories, zero-activity behavior, and privacy patterns. The required top-level fields are:

```text
statement_period
schema_version
calculation_basis
currency
card_volume
transaction_count
gross_processing_fees
statement_credits
total_processing_fees
effective_rate
average_ticket
pricing_model
fee_groups
```

## Run the local validation service

The service wraps the unchanged validator behind a loopback-only HTTP API so other applications can call it without importing Python:

```text
python -m pip install -r requirements-validation.txt -r requirements-service.txt
powershell -File start-service.ps1
```

| Endpoint | Purpose |
|---|---|
| `POST /api/validate` | Validate one JSON audit record (raw JSON body) |
| `POST /api/validate-csv` | Validate a flat CSV template (CSV text body) |
| `GET /api/schema` | Retrieve the JSON Schema contract |
| `GET /api/corpus` | Run the synthetic corpus self-test |
| `GET /api/health` | Service and package version |

The service binds `127.0.0.1:8090`, caps request bodies at one megabyte, and never echoes submitted values in responses. If the `STATEMENT_AUDIT_TOKEN` environment variable is set, every `/api/` request must present it as `Authorization: Bearer <token>` or `X-Audit-Token: <token>`.

## Attribution and reuse

Licensed under [CC BY 4.0](./LICENSE.md). This package is authored and published by Stratamize LLC; [`NOTICE.md`](./NOTICE.md) carries the attribution and licensing notice. Attribute the Stratamize package as:

> Stratamize LLC. (2026). *Stratamize Statement Audit Model* (Version 1.1.0). https://stratamize.com/statement-audit/releases/1.1.0

## Official links

- [Stratamize](https://stratamize.com/)
