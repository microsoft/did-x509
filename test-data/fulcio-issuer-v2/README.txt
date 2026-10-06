Real Fulcio certificate samples
==============================

These public certificates are vendored separately from the method-resolution
cases in the repository-root test-vectors.json. Each PEM file is a complete
leaf-first chain: leaf, intermediate, root. No private keys are included.

- packaging-26.3.pem: production, issued 2026-08-04. Contains Issuer V2 and all
  seventeen standalone extensions .8-.24, including deployment environment
  "pypi" and token subject "repo:pypa/packaging:environment:pypi".
- sigstore-js-2.0.0.pem: production, issued 2023-08-18. Contains .8-.22, but no
  deployment environment (.23) or token subject (.24).
- legacy-staging.pem: staging, issued 2022-07-28. Contains only the legacy
  issuer extension (.1), with no Issuer V2 extension. Its CA chain is the
  staging chain, not the production chain.

All OID suffixes above are relative to 1.3.6.1.4.1.57264.1.

manifest.json records source URLs and extraction locations, SHA-256 hashes of
each certificate's original DER bytes, SAN identities, validity periods, and
expected Fulcio string values. GitHub sources are pinned to commits; the PyPI
source is pinned to a specific distribution version and certificate hash.
Only PEM wrapping was applied: certificate DER bytes and signatures are
unchanged. The source URLs are provenance, not runtime test dependencies.

Each .8-.24 extension contains a DER UTF8String. The legacy .1 extension
contains raw UTF-8. The manifest keeps these values separate, without
normalizing, aliasing, or synthesizing any fields.

The leaf certificates have expired. Offline fixture checks use the reference
resolver's existing no-validity-period-check policy, while still checking the
complete certificate chain. Tests that enforce certificate validity must use
a fixed context-relevant historical time, not the current wall clock.

test_fulcio_issuer_v2_samples.py checks hashes, extension encodings and absence,
and existing SAN/fulcio-issuer resolution using only these vendored files.
These are preparation fixtures, not an implementation of the new fulcio
predicate. V2-only, conflicting-issuer, and malformed-encoding cases still
need separately signed synthetic certificates. OtherName SAN (.7) support
is a separate change and is not covered here.
