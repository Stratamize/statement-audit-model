# Changelog

All notable changes to the versioned dataset package are recorded here. Published release artifacts remain immutable.

## 1.1.0 - 2026-08-06

Privacy, display-safety, and release-determinism hardening. The schema 1.1.0 record contract is unchanged and every record that was valid under 1.0.0 that carries no truncated card reference or Unicode control character remains valid.

- Reject labeled, unlabeled, brand-masked, and first-six/last-five truncated card references in free-text notes, so a note may no longer disclose the last four digits of a PAN.
- Add the `unsafe_text_control` issue code, rejecting Unicode `Cc` and `Cf` control characters that can conceal or reorder displayed audit notes.
- Register three new hostile vectors — `truncated-pan-in-note.json`, `masked-card-brand-in-note.json`, and `unsafe-display-control.json` — bringing the synthetic corpus to 2 accepted and 17 rejected vectors.
- Extend the publication gate's public-content safety check to reject those same Unicode control characters anywhere in declared release text, and tighten the aggregate release-size bound from 25 MiB to 8 MiB in both the gate and the public attestor.
- Build the release ZIP deterministically from the declared manifest with fixed member timestamps, stable ordering, POSIX regular-file mode 0644, a Unix create system, and stored members, so a clean build reproduces identical bytes on every platform.
- Fix a dead symlink guard in the release-archive builder and the checksum writer: both tested the resolved path, which can never be a symlink, and now test the declared path and validate it as a relative, canonical, non-traversing POSIX name.
- Raised `GATE_VERSION` to 2.1.0 to reflect the changed publication-gate behavior.

## 1.0.0 - 2026-08-03

First Stratamize release.

- Established the package identity, titles, URLs, metadata, and release tooling for Stratamize.
- Defined the schema 1.1.0 record contract, the validator rules, and the complete synthetic test-vector corpus.
- Declared Stratamize version and product identifiers as the sole release identity.
- Provided bounded, non-executing GitHub release attestation against the Stratamize repository, which fails closed when public release evidence is unavailable.
- Added a local HTTP validation service (`service/`) exposing the validator on `127.0.0.1:8090`: record validation, CSV-template validation, schema retrieval, corpus self-test, and health, with optional bearer-token auth and a one-megabyte request cap. The service never echoes submitted values.
- Added a deterministic release-archive builder (`tools/build_release_archive.py`) producing the publication zip and SHA-256 sidecar exactly as the attestation expects.
- Release posture: the package gate must pass everywhere; candidate and published modes verify the public repository and release provenance and fail closed when evidence is unavailable.
