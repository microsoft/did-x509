# @didx509/core

> Contributed by [AyanWorks](https://github.com/ayanworks)

TypeScript implementation of the did:x509 DID method.

Bridges X.509 certificate infrastructure with W3C Decentralized Identifiers, enabling you to derive DIDs directly from existing PKI certificates.

Original did:x509 specification by Microsoft Corporation (Maik Riechert, Antoine Delignat-Lavaud).

## Installation

```bash
npm install @didx509/core
```

## Quick Start

```typescript
import { resolveDidFromPem } from '@didx509/core';

const pemChain = readFileSync('chain.pem', 'utf-8');
const did = 'did:x509:0:sha256:ABC...::subject:CN%3Dexample.com';
const doc = await resolveDidFromPem(did, pemChain);
console.log(doc);
```

## API Overview

| Function | Description |
|---|---|
| `resolveDidFromPem(did, pemChain, options?)` | Resolve a did:x509 DID from a PEM certificate chain string. |
| `resolveDid(did, chain, options?)` | Resolve a did:x509 DID from parsed `X509Certificate[]` objects. |
| `convertChain(pemChain)` | Convert a PEM chain to the did:x509 JSON model (`DecodedCertificate[]`). |
| `loadPemCertificateChain(pem)` | Parse a PEM string into an `X509Certificate[]` array. |
| `loadDerCertificateChain(derChain)` | Load certificates from DER-encoded `ArrayBuffer[]`. |
| `loadX509Chain(x509chain)` | Load certificates from comma-separated base64url-encoded DER. |
| `decodeCertificate(cert)` | Decode a single `X509Certificate` into the JSON model. |
| `verifyCertificateChain(chain, skipCheck?)` | Verify chain order, signatures, basic constraints, and validity. |
| `extractPublicKeyAsJwk(cert)` | Export a certificate's public key as a JWK. |
| `computeFingerprint(cert, algorithm)` | Synchronous fingerprint (Node.js only). |
| `computeFingerprintAsync(cert, algorithm)` | Async fingerprint via Web Crypto API. |
| `getKeyUsage(cert)` | Extract digitalSignature / keyAgreement flags. |
| `parseDid(did)` | Parse a did:x509 string into components. |
| `checkDidX509(did, decodedChain)` | Validate a DID against a decoded certificate chain. |
| `createDidDocument(did, chain)` | Build a W3C DID Document from a DID and chain. |
| `getDidX509Resolver()` | Returns a `did-resolver` compatible resolver plugin. |
| `b64url(data)` / `b64urlDecode(str)` | Base64url encode/decode. |
| `pctEncode(data)` / `pctDecode(str)` | Percent-encode/decode per RFC 3986. |
| `parseNameString(nameStr)` | Parse an X.509 name string into a `CertificateName` object. |
| `oidToLabel(oid)` | Convert an OID dotted string to its RFC 4514 label. |

## did-resolver Integration

```typescript
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/core';

const resolver = new Resolver(getDidX509Resolver());

const result = await resolver.resolve(
  'did:x509:0:sha256:ABC...::subject:CN%3Dexample.com',
  {
    x509chain: 'base64url_der1,base64url_der2,...',
  }
);
```

The resolver expects the `x509chain` option containing comma-separated base64url-encoded DER certificates (leaf first). If this option is missing, it returns an `invalidDidResolutionOptions` error.

## CLI Usage

```bash
# Resolve a DID from a PEM chain file
didx509 resolve "did:x509:0:sha256:..." --chain chain.pem

# Skip validity period check (useful for expired test certs)
didx509 resolve "did:x509:0:sha256:..." --chain chain.pem --skip-validity-period-check

# Convert a PEM chain to the did:x509 JSON model
didx509 convert chain.pem

# Percent-encode a string
didx509 encode "CN=example.com"
```

## Platform Support

| Platform | Status |
|---|---|
| Node.js 18+ | Full support (sync and async fingerprint) |
| Deno | Full support (async fingerprint via Web Crypto) |
| Bun | Full support (async fingerprint via Web Crypto) |
| Browser | Full support (async fingerprint via Web Crypto) |
| React Native | Supported via polyfill for `Web Crypto` |

Synchronous `computeFingerprint` requires Node.js `crypto` and will throw in other environments. Use `computeFingerprintAsync` for cross-platform fingerprint computation.

## License

MIT
