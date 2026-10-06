The test certificates in this folder are from public sources:

- ms-*.pem are public Microsoft certificates
- fulcio-*.pem are public certificates from the Fulcio CT log
- fulcio-issuer-v2 contains public production and staging Fulcio certificate
  chains, with provenance and expected extension values in its manifest.json.
  The implementation tests in test_fulcio.py exercise all 17 scoped selectors
  against the unchanged packaging chain and use independently signed synthetic
  certificates for edge cases. Validity periods are not checked by the resolver;
  use a fixed context-relevant historical time if checking these expired leaves.
