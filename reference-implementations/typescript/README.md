# @didx509/core

> Contributed by [AyanWorks](https://github.com/ayanworks)

TypeScript implementation of the did:x509 DID method.

**Bridges your existing X.509 certificates with W3C Decentralized Identifiers** — so you can derive DIDs directly from CA-issued certs and use them across decentralized trust infrastructure.

Original did:x509 specification by Microsoft Corporation (Maik Riechert, Antoine Delignat-Lavaud).

## The Problem

You have an X.509 certificate from a CA. You need a DID for your decentralized trust workflows — issuing credentials, registering in trust registries, verifying presented credentials. You don't want to set up a blockchain or new key infrastructure. Your cert **is** your identity.

## How It Works

```
CA-issued X.509 cert
        │
        ▼
  did:x509 DID ────────► DID Document (public key, capabilities)
        │
        ├─► Issue verifiable credentials (issuer DID)
        ├─► Register in trust registries
        ├─► Verify credentials from holders
        ├─► Authenticate / establish secure channels
        └─► Any workflow that needs a DID + PKI trust chain
```

The DID is derived from your certificate — no blockchain, no additional registration. The DID Document's public key comes directly from your leaf cert. The trust chain is your CA hierarchy.

## Installation

```bash
npm install @didx509/core
```

## Workflow 1: Extract a DID from Your Certificate

You have a PEM certificate chain (leaf + intermediates). Extract the DID:

```typescript
import { convertChain, computeFingerprintAsync } from '@didx509/core';

const pemChain = readFileSync('cert-chain.pem', 'utf-8');

// Parse the chain to see what's inside
const decoded = convertChain(pemChain);
const leaf = decoded[0];
const ca = decoded[decoded.length - 1];

// Extract the CA fingerprint (this becomes your DID identifier)
const caCert = (await import('@peculiar/x509')).loadPemCertificateChain(pemChain);
const fingerprint = await computeFingerprintAsync(
  caCert[caCert.length - 1], 'sha256'
);

// Build the DID
const subjectCN = leaf.subject['2.5.4.3']; // Common Name
const did = `did:x509:0:sha256:${fingerprint}::subject:CN%3D${pctEncode(subjectCN)}`;

console.log(did);
// did:x509:0:sha256:IybVX...A%3D%3D::subject:CN%3Dexample.com
```

See [docs/practical-guide.md](docs/practical-guide.md) for the full extraction workflow with all predicate types (SAN, EKU, O, OU).

## Workflow 2: Issue a Verifiable Credential

Use your DID as the issuer when issuing a credential to a holder:

```typescript
import { resolveDidFromPem } from '@didx509/core';

const pemChain = readFileSync('issuer-cert-chain.pem', 'utf-8');
const issuerDid = 'did:x509:0:sha256:ABC...::subject:CN%3Dmy-org.com';

// Resolve the DID Document (contains the issuer's public key)
const issuerDoc = await resolveDidFromPem(issuerDid, pemChain);

// Use issuerDoc.id and issuerDoc.verificationMethod[0].publicKeyJwk
// as the issuer in your Verifiable Credential:
const credential = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "issuer": issuerDoc.id,
  "issuanceDate": "2025-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder123",
    "degree": "Bachelor of Science"
  },
  "proof": {
    "type": "EcdsaSecp256r1Signature2019",
    "verificationMethod": `${issuerDoc.id}#${issuerDoc.verificationMethod[0].id}`,
    // ... sign with the private key matching the public key in verificationMethod
  }
};
```

## Workflow 3: Verify a Presented Credential

A holder presents a credential. Extract the DID from their certificate and verify:

```typescript
import { resolveDidFromPem, verifyCertificateChain } from '@didx509/core';

const holderPemChain = holderCertChain; // from the presentation
const holderDid = 'did:x509:0:sha256:DEF...::subject:CN%3Dholder.example.com';

// 1. Verify the certificate chain is valid
const chain = loadPemCertificateChain(holderPemChain);
await verifyCertificateChain(chain);

// 2. Resolve the holder's DID Document
const holderDoc = await resolveDidFromPem(holderDid, holderPemChain);

// 3. Use holderDoc.verificationMethod[0].publicKeyJwk to verify
//    the credential's proof signature
```

## Workflow 4: Register in a Trust Registry

Add your entity to a trust registry using your DID:

```typescript
import { resolveDidFromPem, convertChain } from '@didx509/core';

const pemChain = readFileSync('org-cert-chain.pem', 'utf-8');
const orgDid = 'did:x509:0:sha256:GHI...::subject:O%3DMy%20Organization';

const doc = await resolveDidFromPem(orgDid, pemChain);
const decoded = convertChain(pemChain);

// Registration payload for a trust registry
const registration = {
  did: doc.id,
  legalName: decoded[0].subject['2.5.4.10'], // Organization
  domainName: decoded[0].extensions?.san?.[0]?.value, // first SAN
  publicKeyJwk: doc.verificationMethod[0].publicKeyJwk,
  certificateChain: decoded.map(c => c.pem), // for re-verification
  trustFramework: "EBSI", // or your framework
};
```

## Workflow 5: did-resolver Integration

Integrate with the broader DID ecosystem using the `did-resolver` plugin:

```typescript
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/core';

const resolver = new Resolver(getDidX509Resolver());

const result = await resolver.resolve(
  'did:x509:0:sha256:ABC...::subject:CN%3Dexample.com',
  {
    x509chain: 'base64url_der1,base64url_der2,...' // comma-separated base64url DER
  }
);

console.log(result.didDocument);
```

## Quick Reference

| I have... | I want to... | Use |
|---|---|---|
| PEM cert chain | Extract a DID | `convertChain()` + `computeFingerprintAsync()` |
| PEM chain + DID | Get DID Document | `resolveDidFromPem()` |
| X509Certificate[] + DID | Get DID Document | `resolveDid()` |
| DID string | Parse components | `parseDid()` |
| PEM chain | Verify chain validity | `verifyCertificateChain()` |
| Cert public key | Export as JWK | `extractPublicKeyAsJwk()` |
| Cert | Check key usage | `getKeyUsage()` |
| PEM string | Parse to objects | `loadPemCertificateChain()` |

## CLI

```bash
# Extract a DID and resolve it from a PEM chain
didx509 resolve "did:x509:0:sha256:..." --chain chain.pem

# Inspect a PEM chain (see subjects, SANs, fingerprints)
didx509 convert chain.pem

# Percent-encode a value for use in DID strings
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

## Documentation

- **[Practical Guide](docs/practical-guide.md)** — Real-world workflows: cert-to-DID extraction, issuing, verifying, trust registries
- **[Getting Started](docs/getting-started.md)** — Installation, basic usage, encoding utilities
- **[API Reference](docs/api-reference.md)** — Complete function signatures, types, and options

## License

MIT
