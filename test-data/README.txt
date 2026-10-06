The test certificates in this folder are from public sources:

- ms-*.pem are public Microsoft certificates
- fulcio-*.pem are public certificates from the Fulcio CT log
- fulcio-issuer-v2 contains public production and staging Fulcio certificate
  chains, with provenance and expected extension values in its manifest.json.
  The implementation tests in test_fulcio.py exercise all 17 scoped selectors
  against pydantic-ai-2.54.0.pem without altering the public certificate bytes.
  The sigstore-js-2026-08-04.pem sample has a token subject but no deployment
  environment. Missing token subjects and other edge cases use independently
  signed synthetic certificates. Validity periods are not checked by the
  resolver; use a fixed historical context when checking these expired leaves.
