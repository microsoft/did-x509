# Getting Started with @didx509/core

> Contributed by [AyanWorks](https://github.com/ayanworks)

## What is did:x509?

did:x509 derives DIDs directly from X.509 certificates. If you already have a cert from a CA — public, enterprise, or Fulcio — you already have a DID. No blockchain, no new key infrastructure.

```
CA-issued cert ──► did:x509 DID ──► DID Document (public key + capabilities)
```

## Installation

```bash
npm install @didx509/core
```

## The One Thing to Know

Your starting point is always a **PEM certificate chain** and a **did:x509 DID string**. Everything flows from there.

```typescript
const pemChain = readFileSync('cert-chain.pem', 'utf-8');
const did = 'did:x509:0:sha256:ABC...::subject:CN%3Dexample.com';
```

If you don't have the DID string yet, see [Extracting a DID from Your Certificate](#extracting-a-did-from-your-certificate) below.

---

## Step 1: Resolve a DID to a DID Document

Given a cert chain and its DID, get the DID Document (contains the public key):

```typescript
import { resolveDidFromPem } from '@didx509/core';

const doc = await resolveDidFromPem(did, pemChain);

console.log(doc.id);                                    // did:x509:...
console.log(doc.verificationMethod[0].publicKeyJwk);   // JWK public key
console.log(doc.authentication);                        // ["did:x509:...#0"]
```

This is the primary operation. It:
1. Verifies the certificate chain
2. Checks the DID matches the certificate attributes
3. Extracts the public key from the leaf cert
4. Returns a W3C DID Document

---

## Step 2: Extract a DID from Your Certificate

If you have a cert but don't have the DID string yet, derive it:

```typescript
import {
  loadPemCertificateChain,
  decodeCertificate,
  computeFingerprintAsync,
  pctEncode,
} from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
const leaf = chain[0];
const ca = chain.length > 1 ? chain[1] : chain[0];

// Compute the CA fingerprint
const fingerprint = await computeFingerprintAsync(ca, 'sha256');

// Build the DID using the certificate's Common Name
const decoded = decodeCertificate(leaf);
const cn = decoded.subject['2.5.4.3'];
const did = `did:x509:0:sha256:${fingerprint}::subject:CN%3D${pctEncode(cn)}`;

console.log('Your DID:', did);
```

### Choosing a Predicate

The predicate is the part after `::` that identifies you. Pick based on what your cert contains:

| Your cert has... | Use predicate | Example |
|---|---|---|
| Common Name (CN) | `subject:CN=<value>` | `::subject:CN%3Dexample.com` |
| Organization (O) | `subject:O=<value>` | `::subject:O%3DAcme%20Inc` |
| Email in SAN | `san:email=<value>` | `::san:email%3Duser@example.com` |
| DNS name in SAN | `san:dns=<value>` | `::san:dns%3Dexample.com` |
| IP in SAN | `san:ip=<value>` | `::san:ip%3D192.168.1.1` |
| EKU OID | `eku:<oid>` | `::eku:1.3.6.1.5.5.7.3.3` |

**Not sure what's in your cert?** Inspect it:

```typescript
import { convertChain } from '@didx509/core';

const decoded = convertChain(pemChain);
console.log('Subject:', decoded[0].subject);
console.log('SANs:', decoded[0].extensions.san);
console.log('EKUs:', decoded[0].extensions.eku);
```

---

## Step 3: Verify a Certificate Chain

Before trusting a cert, verify the chain:

```typescript
import { loadPemCertificateChain, verifyCertificateChain } from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
await verifyCertificateChain(chain);
// Throws if chain is invalid (bad order, untrusted CA, expired, etc.)
```

---

## Step 4: Export Public Key as JWK

Get the public key in JWK format for use with other libraries:

```typescript
import { loadPemCertificateChain, extractPublicKeyAsJwk } from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
const jwk = extractPublicKeyAsJwk(chain[0]);
// { kty: "EC", crv: "P-256", x: "...", y: "..." }
```

---

## Step 5: Check Key Usage

Verify what the certificate's key is authorized for:

```typescript
import { loadPemCertificateChain, getKeyUsage } from '@didx509/core';

const chain = loadPemCertificateChain(pemChain);
const usage = getKeyUsage(chain[0]);
// { digitalSignature: true, keyEncipherment: false, ... }
```

---

## Step 6: Integrate with did-resolver

Connect to the broader DID ecosystem:

```typescript
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/core';

const resolver = new Resolver(getDidX509Resolver());

const result = await resolver.resolve(did, {
  x509chain: 'base64url_der1,base64url_der2,...'
});
```

---

## Encoding Utilities

```typescript
import { pctEncode, pctDecode, b64url, b64urlDecode, parseNameString } from '@didx509/core';

pctEncode('CN=example.com');              // "CN%3Dexample.com"
pctDecode('CN%3Dexample.com');            // "CN=example.com"
b64url(new Uint8Array([72, 101, 108, 108, 111]));  // "SGVsbG8"
parseNameString('CN=example.com, O=Acme'); // { '2.5.4.3': 'example.com', '2.5.4.10': 'Acme' }
```

---

## What's Next

- **[Practical Guide](practical-guide.md)** — Real-world workflows: issuing credentials, verifying presentations, trust registry registration, Fulcio/Sigstore integration
- **[API Reference](api-reference.md)** — Complete function signatures, all types, and options
