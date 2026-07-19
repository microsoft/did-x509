# did:x509

This repository contains the specification and reference implementations of the did:x509 [DID](https://www.w3.org/TR/did-core/) method. It aims to achieve interoperability between existing X.509 solutions and Decentralized Identifiers (DIDs) to support operational models in which a full transition to DIDs is not achievable or desired yet. It is registered as a [DID method](https://w3c.github.io/did-extensions/methods/) with the did-wg in the W3C.

## Specification

See [specification.md](specification.md).

## Reference Implementations

| Language | Maintainer | Location |
|----------|-----------|----------|
| Python | Microsoft (original) | [`reference-implementations/python/`](reference-implementations/python/) |
| TypeScript | [AyanWorks](https://github.com/ayanworks) | [`reference-implementations/typescript/`](reference-implementations/typescript/) |

### Python

First, install the required Python packages:

```sh
pip install -r reference-implementations/python/requirements.txt
```

Then, run the resolver with an example DID and matching certificate chain:

```sh
python -m didx509 resolve did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation --chain reference-implementations/python/test-data/ms-code-signing.pem --skip-validity-period-check
```

Run tests:

```sh
cd reference-implementations/python && pytest -v test.py
```

### TypeScript

> Contributed by [AyanWorks](https://github.com/ayanworks)

The TypeScript implementation (`@didx509/core`) is a cross-runtime package that works in Node.js, Deno, Bun, browsers, and React Native.

```sh
cd reference-implementations/typescript
npm install
npm test
```

Quick usage:

```typescript
import { resolveDidFromPem } from '@didx509/core';

const doc = await resolveDidFromPem(
  'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation',
  pemCertificateChain,
  { skipValidityPeriodCheck: true }
);
```

See the [TypeScript README](reference-implementations/typescript/README.md) for full documentation.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

## Credits

- **Specification**: did:x509 method specification by Microsoft Corporation (Maik Riechert, Antoine Delignat-Lavaud)
- **TypeScript implementation**: Contributed by [AyanWorks](https://github.com/ayanworks)

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft's Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
