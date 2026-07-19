# did:x509

This repository contains the specification and reference implementations of the did:x509 [DID](https://www.w3.org/TR/did-core/) method. It aims to achieve interoperability between existing X.509 solutions and Decentralized Identifiers (DIDs) to support operational models in which a full transition to DIDs is not achievable or desired yet. It is registered as a [DID method](https://w3c.github.io/did-extensions/methods/) with the did-wg in the W3C.

## Why did:x509?

If you already hold an X.509 certificate from a CA — whether public PKI, enterprise PKI, or Fulcio/Sigstore — you already have a DID. No blockchain, no new key infrastructure, no additional registration.

```
CA-issued X.509 cert ──► did:x509 DID ──► Use across decentralized trust infrastructure
```

This enables you to:
- **Issue verifiable credentials** using your DID as the issuer identifier
- **Verify credentials** presented by holders with CA-backed identity
- **Register in trust registries** using your cert-derived DID
- **Sign software artifacts** (Fulcio/Sigstore) with a DID identity
- **Bridge enterprise PKI** to decentralized identity workflows

See the [Practical Guide](reference-implementations/typescript/docs/practical-guide.md) for real-world workflows.

## Specification

See [specification.md](specification.md).

## Reference Implementations

| Language | Maintainer | Location |
|----------|-----------|----------|
| Python | Microsoft (original) | [`reference-implementations/python/`](reference-implementations/python/) |
| TypeScript | [AyanWorks](https://github.com/ayanworks) | [`reference-implementations/typescript/`](reference-implementations/typescript/) |

### TypeScript (@didx509/core)

Cross-runtime package (Node.js, Deno, Bun, browser, React Native). Derives DIDs from your existing CA-issued certificates.

```bash
cd reference-implementations/typescript
npm install
npm test
```

```typescript
import { resolveDidFromPem } from '@didx509/core';

const doc = await resolveDidFromPem(did, pemChain);
console.log(doc.verificationMethod[0].publicKeyJwk);
```

- **[Practical Guide](reference-implementations/typescript/docs/practical-guide.md)** — Cert-to-DID extraction, issuing, verifying, trust registries
- **[Getting Started](reference-implementations/typescript/docs/getting-started.md)** — Installation and basic usage
- **[API Reference](reference-implementations/typescript/docs/api-reference.md)** — Complete function signatures and types

### Python

```bash
cd reference-implementations/python
pip install -r requirements.txt
pytest -v test.py
```

```bash
python -m didx509 resolve "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation" \
  --chain test-data/ms-code-signing.pem --skip-validity-period-check
```

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

## Credits

- **Specification**: did:x509 method specification by Microsoft Corporation (Maik Riechert, Antoine Delignat-Lavaud)
- **TypeScript implementation**: Contributed by [AyanWorks](https://github.com/ayanworks)

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft's Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
