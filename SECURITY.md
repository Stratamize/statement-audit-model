# Security policy and publication threat model

## Supported release

Security fixes are applied to the newest versioned release. Published release artifacts are immutable; a fix receives a new release, checksums, validation report, and Stratamize version identifier.

## What the publication gate defends

The release gate is designed to fail closed when it encounters:

- a malformed, incomplete, duplicated, absolute, or path-traversing manifest;
- an undeclared file in the candidate release tree;
- a missing, symlinked, non-UTF-8, or non-LF declared artifact;
- an excessive file count, individual asset size, or aggregate release size;
- a checksum mismatch or undeclared security-critical file;
- a validator that fails, times out, emits malformed output, or does not reproduce the corpus;
- a candidate validator that fails its bounded behavioral regression suite;
- an unpinned validation dependency or stale validation report;
- inconsistent package, schema, citation, identifier, or source-release identity;
- a candidate that reuses an existing release version while changing its tagged files;
- a tagless archive or incomplete clone presented as publication-ready;
- a dirty or uncommitted candidate tree;
- an origin outside the authoritative Stratamize repository;
- an unavailable, malformed, missing, divergent, or non-monotonic remote release tag;
- common private-key, cloud-key, repository-token, model-token, chat-token, or live payment-key signatures anywhere in the declared release;
- Unicode control characters that can conceal or reorder displayed release text; or
- synthetic records that violate structural, accounting, precision, period, privacy, size, depth, safe-number, or spreadsheet-formula rules.

Candidate validation runs in a bounded child process and must return a machine-readable corpus report. Gate output contains fixed rule messages and hashes, never released file contents or submitted statement values.

## Assurance modes and execution order

`--mode package` is portable and proves internal consistency only. Its successful status is `valid`, never `ready` or `verified`. `--mode candidate` is the publication boundary and requires a real clean Git worktree, committed byte identity, the authoritative origin, and a complete remote tag inventory. `--mode published` additionally verifies public release and archive evidence; a network, rate-limit, redirect, digest, or identity failure blocks rather than falling back to local success.

The gate performs bounded manifest, path, inventory, size, encoding, checksum, secret-signature, unsafe-text-control, identity, Git, and tag checks before it executes the candidate validator or its behavioral regression suite. This prevents an untrusted or incomplete candidate from reaching the executable portion of the workflow merely because it can rewrite its own checksum file.

Build ordering is deliberately not load-bearing. `dist/` holds only the built publication archive and its SHA-256 sidecar; it is ignored by Git and excluded from release-file discovery, so producing the archive never introduces an undeclared file and never changes a gate result. A `.git`-less extraction of a release therefore reaches the same `--mode package` verdict as the maintainer's in-place run. The release procedure still regenerates in a fixed order — corpus report, then `update_checksums.py --write`, then `build_release_archive.py`, then the full test suite and all four gates last — so the verified tree and the shipped tree are always the same bytes.

## Trust boundaries and non-goals

This repository accepts only statement-level aggregates. It is not designed to ingest source statements, cardholder data, bank data, merchant-owner data, credentials, or secrets. Automated pattern screening is defense in depth; it cannot prove arbitrary prose contains no identifying or confidential information. Human review remains mandatory before any record is made public.

The gate establishes reproducibility, internal consistency, and declared release provenance. It is not a malware sandbox, digital signature, accounting opinion, legal determination, interchange-qualification audit, or guarantee that a mapped source statement is complete. Run executable candidate validation only on a locally reviewed checkout. Published mode verifies release identity and bytes; it does not make arbitrary contributed Python safe to execute.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting workflow in the Security tab of https://github.com/Stratamize/statement-audit-model. If GitHub is unavailable, report privately to josephneese@stratamize.com. Do not include real merchant statements, PANs, authentication data, bank details, credentials, or other sensitive values in a report. A minimal synthetic reproducer is sufficient.
