# Practical Guide: Real-World Workflows

> Contributed by [AyanWorks](https://github.com/ayanworks)

This guide walks through the practical business workflows where did:x509 solves real problems — from holding a CA-issued certificate to using it across decentralized trust infrastructure.

## Overview: Your Cert Is Your Identity

```
                    ┌─────────────────────────────┐
                    │  Certificate Authority (CA)  │
                    │  (Public, Enterprise, Fulcio)│
                    └──────────┬──────────────────┘
                               │ Issues cert
                               ▼
                    ┌─────────────────────────────┐
                    │   X.509 Certificate Chain    │
                    │  (Leaf + Intermediates)      │
                    └──────────┬──────────────────┘
                               │ Extract DID
                               ▼
        ┌──────────────────────────────────────────────┐
        │              did:x509 DID                    │
        │  did:x509:0:sha256:<CA fingerprint>::<predicate>  │
        └──────┬───────────┬───────────┬──────────────┘
               │           │           │
               ▼           ▼           ▼
        ┌─────────┐ ┌───────────┐ ┌──────────┐
        │  Issue   │ │  Verify   │ │  Trust   │
        │ Creds    │ │  Creds    │ │ Registry │
        └─────────┘ └───────────┘ └──────────┘
```

You don't need a blockchain, a new key pair, or a separate registration step. Your CA-issued certificate **is** the root of your DID identity.

---

## Step 1: Extract a DID from Your Certificate

### What You Need

- Your PEM certificate chain (leaf certificate + any intermediates, root CA optional)
- This is the same chain you received from your CA — no special format needed

### How to Extract

```typescript
import {
  loadPemCertificateChain,
  computeFingerprintAsync,
  decodeCertificate,
  pctEncode,
} from '@didx509/core';

const pemChain = readFileSync('my-cert-chain.pem', 'utf-8');
const chain = loadPemCertificateChain(pemChain);

// The leaf certificate (first in chain) contains your identity
const leaf = chain[0];
const decoded = decodeCertificate(leaf);

// The CA certificate (second in chain, or last if only two)
const caCert = chain.length > 1 ? chain[1] : chain[0];

// Compute the CA fingerprint — this is the core DID identifier
const fingerprint = await computeFingerprintAsync(caCert, 'sha256');

// Choose your predicate based on what identifies you:
const cn = decoded.subject['2.5.4.3']; // Common Name
const did = `did:x509:0:sha256:${fingerprint}::subject:CN%3D${pctEncode(cn)}`;

console.log('Your DID:', did);
// Example: did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN%3DMy%20Organization
```

### Predicate Options

Your DID can encode different identity claims depending on what your certificate contains:

| Predicate | Certificate Field | Example DID Fragment |
|---|---|---|
| `subject:CN=<value>` | Common Name | `::subject:CN%3Dexample.com` |
| `subject:O=<value>` | Organization | `::subject:O%3DAcme%20Inc` |
| `subject:OU=<value>` | Org Unit | `::subject:OU%3DEngineering` |
| `san:<type>=<value>` | Subject Alt Name | `::san:email%3Duser@example.com` |
| `san:dns=<value>` | DNS SAN | `::san:dns%3Dexample.com` |
| `san:ip=<value>` | IP SAN | `::san:ip%3D192.168.1.1` |
| `eku:<oid>` | Extended Key Usage | `::eku:1.3.6.1.5.5.7.3.3` |
| Multiple predicates | Combined | `::subject:O%3DAcme::san:email%3Da@b.com` |

**Choosing the right predicate:**

- **`subject:CN`** — Most common. Use when your cert has a meaningful CN (e.g., domain name, org name).
- **`san:email`** — Use for personal/individual identity (Fulcio-style certs).
- **`san:dns`** — Use for service/domain identity (TLS certs).
- **`eku`** — Use to express the certificate's intended purpose (code signing, email protection, etc.).
- **Combined** — Use multiple predicates when you need stronger identity binding.

### Inspecting an Unknown Certificate

Not sure what's in your cert? Use `convertChain` to see everything:

```typescript
import { convertChain } from '@didx509/core';

const decoded = convertChain(pemChain);

for (const cert of decoded) {
  console.log('--- Certificate ---');
  console.log('Subject:', cert.subject);
  console.log('Issuer:', cert.issuer);
  console.log('SANs:', cert.extensions.san);
  console.log('EKUs:', cert.extensions.eku);
  console.log('Key Usage:', cert.extensions.keyUsage);
  console.log('SHA-256 Fingerprint:', cert.fingerprint.sha256);
}
```

---

## Step 2: Issue a Verifiable Credential (Issuer Role)

You're an issuer — a university, employer, CA, or government agency. You want to issue a verifiable credential using your DID as the issuer identifier.

### The Flow

```
1. You have: cert chain + extracted DID
2. Resolve DID → DID Document (contains your public key)
3. Sign the credential with your private key
4. Embed your DID as the issuer in the credential
```

### Code

```typescript
import {
  resolveDidFromPem,
  loadPemCertificateChain,
  extractPublicKeyAsJwk,
} from '@didx509/core';
import { signCredential } from './your-signing-library'; // your VC library

// Your cert chain and DID
const pemChain = readFileSync('issuer-cert.pem', 'utf-8');
const issuerDid = 'did:x509:0:sha256:ABC...::subject:CN%3Dmy-university.edu';

// 1. Resolve the DID Document
const issuerDoc = await resolveDidFromPem(issuerDid, pemChain);

// 2. Build the credential
const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": ["VerifiableCredential", "DegreeCredential"],
  "issuer": issuerDoc.id,  // did:x509:0:sha256:ABC...::subject:CN%3Dmy-university.edu
  "issuanceDate": new Date().toISOString(),
  "credentialSubject": {
    "id": "did:example:student456",
    "name": "Jane Doe",
    "degree": "Bachelor of Science",
    "fieldOfStudy": "Computer Science"
  }
};

// 3. Sign the credential
// The verificationMethod points to your DID + key ID
const verificationMethod = `${issuerDoc.id}#${issuerDoc.verificationMethod[0].id}`;

const signedCredential = await signCredential(credential, {
  verificationMethod,
  privateKey: yourPrivateKey, // must match the public key in the DID Document
  proofPurpose: "assertionMethod"
});

// 4. The credential is now ready to send to the holder
console.log('Signed credential issuer:', signedCredential.issuer);
console.log('Verification method:', signedCredential.proof.verificationMethod);
```

### What the Verifier Sees

When someone verifies this credential, they:
1. See the issuer DID: `did:x509:0:sha256:ABC...::subject:CN%3Dmy-university.edu`
2. Resolve the DID by presenting the cert chain → get the DID Document
3. Verify the proof signature against the DID Document's public key
4. Optionally verify the cert chain back to the trusted CA

---

## Step 3: Verify a Presented Credential (Verifier Role)

A holder presents a credential to you. You need to verify it's legitimate.

**Key insight:** You do NOT need to extract a DID from the holder's certificate to verify the credential. Credential verification is about checking the **issuer's signature**, not the holder's identity. The holder's cert chain is only needed if you want to authenticate who presented it.

### The Flow: Verify the Credential

```
1. You receive: a signed credential
2. Look up the issuer DID from the credential
3. Resolve the issuer's DID Document (requires issuer's cert chain)
4. Verify the credential's proof signature against the issuer's public key
5. Optionally check the issuer in a trust registry
```

### Code: Verify the Credential

```typescript
import { resolveDidFromPem } from '@didx509/core';
import { verifyCredentialProof } from './your-verification-library';

async function verifyCredential(
  credential: any,
  issuerPemChain: string  // issuer's cert chain, NOT the holder's
) {
  // 1. The issuer DID is embedded in the credential
  const issuerDid = credential.issuer;
  // e.g. "did:x509:0:sha256:ABC...::subject:CN%3Dmy-university.edu"

  // 2. Resolve the issuer's DID Document (contains the issuer's public key)
  const issuerDoc = await resolveDidFromPem(issuerDid, issuerPemChain);

  // 3. Verify the credential's proof against the issuer's public key
  const publicKeyJwk = issuerDoc.verificationMethod[0].publicKeyJwk;
  const isValid = await verifyCredentialProof(credential, publicKeyJwk);

  return {
    valid: isValid,
    issuerDid,
    publicKey: publicKeyJwk,
  };
}
```

### Optional: Authenticate the Holder

If the holder presents a Verifiable Presentation (VP) and you need to prove **they control the holder's key** (not just that the credential is valid), then you verify the holder's certificate chain. This is separate from credential verification:

```typescript
import {
  resolveDidFromPem,
  loadPemCertificateChain,
  verifyCertificateChain,
} from '@didx509/core';
import { verifyPresentationProof } from './your-verification-library';

async function verifyPresentation(
  presentation: any,          // Verifiable Presentation
  holderPemChain: string      // holder's cert chain (in the VP)
) {
  // 1. Verify the holder's cert chain
  const chain = loadPemCertificateChain(holderPemChain);
  await verifyCertificateChain(chain);

  // 2. Resolve the holder's DID from their cert
  //    (only needed if you want the holder's DID for logging/access control)
  const holderDid = extractDidFromChain(chain); // your extraction logic
  const holderDoc = await resolveDidFromPem(holderDid, holderPemChain);

  // 3. Verify the VP's proof against the holder's public key
  const holderKey = holderDoc.verificationMethod[0].publicKeyJwk;
  const isValid = await verifyPresentationProof(presentation, holderKey);

  return { valid: isValid, holderDid: holderDoc.id };
}
```

### Verification Checklist

| Step | What It Ensures | Required? |
|---|---|---|
| Verify credential proof | Credential was signed by the issuer's private key | Yes |
| Resolve issuer DID | Issuer identity is valid and has a public key | Yes |
| Check issuer trust registry | Issuer is approved for this credential type | Recommended |
| Verify holder cert chain | Holder's cert was issued by a trusted CA | Only for VP authentication |
| Resolve holder DID | Holder identity for access control/logging | Only for VP authentication |

---

## Step 4: Register in a Trust Registry

Trust registries list approved issuers for specific credential types. Your DID is your registration identity.

### Registration Flow

```
1. Extract DID from your cert chain
2. Build registration payload with DID + cert metadata
3. Submit to trust registry
4. Registry verifies your DID (resolves it, checks cert chain)
5. You're listed as an approved issuer
```

### Registration Payload

```typescript
import { resolveDidFromPem, convertChain, extractPublicKeyAsJwk } from '@didx509/core';

const pemChain = readFileSync('org-cert.pem', 'utf-8');
const orgDid = 'did:x509:0:sha256:GHI...::subject:O%3DMy%20Organization';

const doc = await resolveDidFromPem(orgDid, pemChain);
const decoded = convertChain(pemChain);

// Build the registration entry
const registration = {
  // Identity
  did: doc.id,
  legalName: decoded[0].subject['2.5.4.10'],           // Organization
  commonName: decoded[0].subject['2.5.4.3'],           // Common Name
  domainName: decoded[0].extensions?.san?.[0]?.value,   // first SAN

  // Cryptographic proof
  publicKeyJwk: doc.verificationMethod[0].publicKeyJwk,
  keyType: doc.verificationMethod[0].type,

  // Chain of trust (for the registry to re-verify)
  certificateChain: decoded.map(c => ({
    subject: c.subject,
    issuer: c.issuer,
    fingerprint: c.fingerprint.sha256,
    pem: c.pem,
  })),

  // Metadata
  trustFramework: 'EBSI',          // or your framework
  credentialTypes: ['VerifiableCredential', 'UniversityDegree'],
  status: 'approved',
  registrationDate: new Date().toISOString(),
};

// Submit to your trust registry
await trustRegistry.register(registration);
```

### Trust Registry Verification Flow

When a verifier checks your registry entry:

```
Registry entry contains your DID
        │
        ▼
Resolve DID by presenting the cert chain
        │
        ▼
DID Document's public key matches the cert's public key
        │
        ▼
Cert chain verifies back to a trusted root CA
        │
        ▼
Issuer is approved in the registry
```

---

## Step 5: Fulcio / Sigstore Integration

If you're working with [Fulcio](https://www.sigstore.dev/) (used in Sigstore for signing container images, binaries, and software artifacts), did:x509 is the natural DID method because Fulcio issues short-lived X.509 certificates.

### Extract DID from a Fulcio Certificate

```typescript
import {
  loadPemCertificateChain,
  computeFingerprintAsync,
  decodeCertificate,
  pctEncode,
} from '@didx509/core';

const fulcioPem = readFileSync('fulcio-cert.pem', 'utf-8');
const chain = loadPemCertificateChain(fulcioPem);
const leaf = chain[0];
const decoded = decodeCertificate(leaf);

// Fulcio certs typically have email in SAN
const email = decoded.extensions.san?.find(s => s.type === 'email')?.value;
const did = `did:x509:0:sha256:${await computeFingerprintAsync(chain[1], 'sha256')}::san:email%3D${pctEncode(email)}`;

console.log('Fulcio DID:', did);
```

### Software Artifact Signing

```typescript
// 1. Signer has a Fulcio cert → derives DID
// 2. Signs the artifact with their private key
// 3. Embeds DID in the signature metadata
// 4. Verifier resolves the DID and checks the cert chain

const signatureEnvelope = {
  "payloadType": "application/vnd.dev.sigstore.v0.1+json",
  "signatures": [{
    "keyid": signerDid, // did:x509:0:sha256:...::san:email%3Duser@example.com
    "sig": base64urlEncodedSignature
  }]
};
```

---

## Workflow Summary

| I am a... | I have... | I use did:x509 to... |
|---|---|---|
| **Certificate holder** | CA-issued cert chain | Extract a DID, no new infrastructure needed |
| **Credential issuer** | Cert + DID | Resolve DID Document, sign VCs with DID as issuer |
| **Credential verifier** | Presented cert + credential | Verify chain, resolve DID, check proof |
| **Trust registry operator** | Approved CAs | Map CA-issued certs to DIDs for registry entries |
| **Software signer** | Fulcio/Sigstore cert | Derive DID for artifact signing identity |
| **Enterprise security** | Internal PKI certs | Bridge enterprise PKI to decentralized identity |

---

## Common Patterns

### Pattern: DID from PEM (Most Common)

```typescript
import { resolveDidFromPem } from '@didx509/core';

// This single call handles: chain verification → DID Document creation
const doc = await resolveDidFromPem(did, pemChain);
```

### Pattern: Inspect Cert, Then Decide Predicate

```typescript
import { convertChain, parseNameString, pctEncode } from '@didx509/core';

const decoded = convertChain(pemChain);
const leaf = decoded[0];

// Decide predicate based on what's in the cert
let predicate: string;
if (leaf.extensions.san?.some(s => s.type === 'email')) {
  const email = leaf.extensions.san.find(s => s.type === 'email')!.value;
  predicate = `san:email%3D${pctEncode(email)}`;
} else if (leaf.subject['2.5.4.3']) {
  predicate = `subject:CN%3D${pctEncode(leaf.subject['2.5.4.3'])}`;
} else {
  throw new Error('No suitable predicate found in certificate');
}
```

### Pattern: Multi-Predicate DID for Strong Binding

```typescript
// Combine multiple certificate attributes for stronger identity binding
const cn = decoded[0].subject['2.5.4.3'];
const ou = decoded[0].subject['2.5.4.11'];
const did = `did:x509:0:sha256:${fingerprint}::subject:CN%3D${pctEncode(cn)}::subject:OU%3D${pctEncode(ou)}`;
```

### Pattern: Cross-Platform (Node, Deno, Bun, Browser)

```typescript
// Always use the async version for cross-platform support
const fingerprint = await computeFingerprintAsync(caCert, 'sha256');
// Works everywhere — no Node.js crypto dependency
```

---

## Next Steps

- **[API Reference](api-reference.md)** — All functions, types, and options
- **[Getting Started](getting-started.md)** — Installation and basic setup
- **[did:x509 Specification](https://www.w3.org/TR/did-x509/)** — The full W3C specification
