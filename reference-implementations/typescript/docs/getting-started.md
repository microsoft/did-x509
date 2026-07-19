# Getting Started with @didx509/core

> Contributed by [AyanWorks](https://github.com/ayanworks)

## What is did:x509?

did:x509 is a W3C Decentralized Identifier (DID) method that derives DIDs directly from X.509 certificates. Instead of registering a DID on a blockchain or distributed ledger, the DID is encoded using information from an existing PKI certificate chain — the CA fingerprint, subject attributes, SANs, and extended key usages.

A did:x509 DID looks like:

```
did:x509:0:sha256:IybVX...A%3D%3D::subject:CN%3Dexample.com
```

This encodes:
- **Method**: `x509`
- **Version**: `0`
- **Fingerprint algorithm**: `sha256`
- **CA fingerprint**: `IybVX...A%3D%3D` (base64url)
- **Predicate**: `subject:CN%3Dexample.com` (CN = "example.com", percent-encoded)

## How It Bridges X.509 and DID Ecosystems

The did:x509 method bridges two worlds:

- **X.509 / PKI**: The existing global trust infrastructure used by TLS, S/MIME, and code signing. Certificates are issued by Certificate Authorities and carry subject identity, public keys, and policy constraints.
- **DIDs**: W3C Decentralized Identifiers that enable self-sovereign identity, verifiable credentials, and decentralized authentication without a central authority.

With did:x509, any entity that holds an X.509 certificate — whether from a public CA, an internal enterprise CA, or a tool like Fulcio — automatically has a DID. No additional registration step is needed. The DID can be resolved by presenting the certificate chain, and the DID Document's public key is derived directly from the leaf certificate.

## When to Use did:x509

| Use Case | did:x509 | did:key | did:web |
|---|---|---|---|
| Already have X.509 certificates | Best choice | Requires new key | Requires web hosting |
| Need PKI trust chain | Native support | No chain | No chain |
| Fulcio/Sigstore signing identities | Best choice | No chain | No chain |
| Need DID without any infrastructure | Not suitable (need cert) | Best choice | Requires hosting |
| Enterprise PKI environments | Best choice | Possible | Possible |

## Installation

```bash
npm install @didx509/core
```

## Basic Usage

### Resolving a DID from a PEM Chain

The most common operation: given a DID and a PEM certificate chain, produce a W3C DID Document.

```typescript
import { resolveDidFromPem } from '@didx509/core';

const pemChain = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wI...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBmDCCAoCg...
-----END CERTIFICATE-----`;

const did = 'did:x509:0:sha256:IybVX...::subject:CN%3Dexample.com';

const doc = await resolveDidFromPem(did, pemChain);
console.log(doc.id);
console.log(doc.verificationMethod[0].publicKeyJwk);
```

### Converting a PEM Chain to the JSON Model

Parse a PEM chain into the did:x509 JSON representation for inspection or storage:

```typescript
import { convertChain } from '@didx509/core';

const pemChain = readFileSync('chain.pem', 'utf-8');
const decoded = convertChain(pemChain);

for (const cert of decoded) {
  console.log('Subject:', cert.subject);
  console.log('Fingerprint (sha256):', cert.fingerprint.sha256);
  console.log('SANs:', cert.extensions.san);
  console.log('EKUs:', cert.extensions.eku);
}
```

### Resolving with Already-Loaded Certificates

If you already have `X509Certificate` objects (e.g., from `@peculiar/x509`), use `resolveDid` directly:

```typescript
import { resolveDid, loadPemCertificateChain } from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
const doc = await resolveDid(did, chain, {
  skipValidityPeriodCheck: true,
});
```

### Computing Fingerprints

Fingerprints are the foundation of did:x509 DID identifiers:

```typescript
import {
  loadPemCertificateChain,
  computeFingerprintAsync,
} from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
const ca = chain[1]; // CA certificate (second in chain)

// Cross-platform async version
const sha256 = await computeFingerprintAsync(ca, 'sha256');
const sha384 = await computeFingerprintAsync(ca, 'sha384');
const sha512 = await computeFingerprintAsync(ca, 'sha512');
```

### Parsing a DID String

Deconstruct a did:x509 DID into its components:

```typescript
import { parseDid } from '@didx509/core';

const parsed = parseDid('did:x509:0:sha256:ABC...::subject:CN%3Dexample.com');
console.log(parsed.caFingerprintAlgorithm); // "sha256"
console.log(parsed.caFingerprint);          // "ABC..."
console.log(parsed.predicates);             // [["subject", "CN%3Dexample.com"]]
```

### Encoding Utilities

```typescript
import { pctEncode, b64url, b64urlDecode, parseNameString } from '@didx509/core';

// Percent-encode values for DID URLs
pctEncode('CN=example.com');  // "CN%3Dexample.com"

// Base64url encode/decode certificate DER
const encoded = b64url(derBytes);
const decoded = b64urlDecode(encoded);

// Parse X.509 name strings
const name = parseNameString('CN=example.com, O=Acme Inc');
// { "2.5.4.3": "example.com", "2.5.4.10": "Acme Inc" }
```

## Next Steps

- Read the [API Reference](./api-reference.md) for complete function signatures and all type definitions.
- See the [did-resolver integration](../README.md#did-resolver-integration) section for connecting with the broader DID ecosystem.
