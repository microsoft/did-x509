# API Reference

> Contributed by [AyanWorks](https://github.com/ayanworks)

Complete API reference for `@didx509/core`.

## Core Resolution

### `resolveDidFromPem`

```typescript
async function resolveDidFromPem(
  did: string,
  pemChain: string,
  options?: ResolveOptions
): Promise<DidDocument>
```

Resolve a did:x509 DID from a PEM certificate chain string. This is the primary entry point for most use cases.

**Parameters:**
- `did` — The did:x509 DID string to resolve.
- `pemChain` — A PEM-encoded certificate chain (leaf first, root last), concatenated in a single string.
- `options` — Optional resolution settings.

**Returns:** A W3C DID Document.

**Throws** if the chain fails verification or the DID does not match the certificate.

```typescript
const doc = await resolveDidFromPem(did, pemChain);
```

---

### `resolveDid`

```typescript
async function resolveDid(
  did: string,
  chain: X509Certificate[],
  options?: ResolveOptions
): Promise<DidDocument>
```

Resolve a did:x509 DID from an already-loaded array of `X509Certificate` objects (leaf first, root last).

**Parameters:**
- `did` — The did:x509 DID string to resolve.
- `chain` — Array of `X509Certificate` objects, leaf first.
- `options` — Optional resolution settings.

**Returns:** A W3C DID Document.

---

### `createDidDocument`

```typescript
async function createDidDocument(
  did: string,
  chain: X509Certificate[]
): Promise<DidDocument>
```

Create a W3C DID Document from a validated DID and certificate chain. The DID must already be validated via `checkDidX509`. Extracts the leaf certificate's public key as JWK and sets `authentication`, `assertionMethod`, and `keyAgreement` based on key usage.

**Parameters:**
- `did` — The validated DID string (or DID Document ID).
- `chain` — Array of `X509Certificate` objects.

**Returns:** A DID Document with `@context: "https://www.w3.org/ns/cid/v1"`.

---

### `checkDidX509`

```typescript
function checkDidX509(did: string, decodedChain: DecodedCertificate[]): string
```

Validate a did:x509 DID against a decoded certificate chain. Checks CA fingerprint and all predicates (`subject`, `san`, `eku`, `fulcio-issuer`).

**Parameters:**
- `did` — The did:x509 DID string.
- `decodedChain` — Array of `DecodedCertificate` objects.

**Returns:** The DID Document ID string (DID without fragment).

**Throws** if any validation fails.

---

### `parseDid`

```typescript
function parseDid(did: string): ParsedDid
```

Parse a did:x509 DID string into its components.

**Parameters:**
- `did` — A did:x509 DID string.

**Returns:** A `ParsedDid` object with parsed components.

**Throws** if the DID format is invalid.

```typescript
const parsed = parseDid('did:x509:0:sha256:ABC...::subject:CN%3Dexample.com');
parsed.didDocumentId;         // "did:x509:0:sha256:ABC...::subject:CN%3Dexample.com"
parsed.caFingerprintAlgorithm; // "sha256"
parsed.caFingerprint;          // "ABC..."
parsed.predicates;             // [["subject", "CN%3Dexample.com"]]
```

---

### `convertChain`

```typescript
function convertChain(pemChain: string): DecodedCertificate[]
```

Convert a PEM certificate chain to the did:x509 JSON model representation.

**Parameters:**
- `pemChain` — A PEM-encoded certificate chain string.

**Returns:** Array of `DecodedCertificate` objects (leaf first).

```typescript
const decoded = convertChain(pemChain);
// [{ fingerprint: {...}, issuer: {...}, subject: {...}, extensions: {...} }, ...]
```

---

## X.509 Operations

### `loadPemCertificateChain`

```typescript
function loadPemCertificateChain(pem: string): X509Certificate[]
```

Parse a PEM string into an array of `X509Certificate` objects, ordered leaf-first.

**Parameters:**
- `pem` — A concatenated PEM certificate chain string.

**Returns:** Array of `X509Certificate` objects.

---

### `loadDerCertificateChain`

```typescript
function loadDerCertificateChain(derChain: ArrayBuffer[]): X509Certificate[]
```

Load certificate chain from DER-encoded `ArrayBuffer` objects.

**Parameters:**
- `derChain` — Array of DER-encoded certificate buffers.

**Returns:** Array of `X509Certificate` objects.

---

### `loadX509Chain`

```typescript
function loadX509Chain(x509chain: string): X509Certificate[]
```

Load certificate chain from a comma-separated string of base64url-encoded DER certificates. This format is used by the `did-resolver` plugin's `x509chain` option.

**Parameters:**
- `x509chain` — Comma-separated base64url-encoded DER certificates.

**Returns:** Array of `X509Certificate` objects.

```typescript
const chain = loadX509Chain('base64url_der1,base64url_der2');
```

---

### `decodeCertificate`

```typescript
function decodeCertificate(cert: X509Certificate): DecodedCertificate
```

Decode a single X.509 certificate into the did:x509 JSON model representation. Extracts fingerprints (SHA-256, SHA-384, SHA-512), issuer/subject names, and extensions (SAN, EKU, Fulcio issuer).

**Parameters:**
- `cert` — An `X509Certificate` object.

**Returns:** A `DecodedCertificate`.

---

### `verifyCertificateChain`

```typescript
async function verifyCertificateChain(
  chain: X509Certificate[],
  skipValidityPeriodCheck?: boolean
): Promise<void>
```

Verify a certificate chain: validates chain order, cryptographic signatures, basic constraints (CA flag, path length), and optionally the validity period.

**Parameters:**
- `chain` — Array of `X509Certificate` objects (leaf first, root last). Must have at least 2 certificates.
- `skipValidityPeriodCheck` — If `true`, skip `notBefore`/`notAfter` checks. Default `false`.

**Throws** if any verification step fails.

---

### `extractPublicKeyAsJwk`

```typescript
async function extractPublicKeyAsJwk(cert: X509Certificate): Promise<Record<string, unknown>>
```

Extract the public key from a certificate as a JWK object using the Web Crypto API.

**Parameters:**
- `cert` — An `X509Certificate` object.

**Returns:** JWK object (e.g., `{ kty, crv, x, y }` for EC keys).

---

### `computeFingerprint`

```typescript
function computeFingerprint(
  cert: X509Certificate,
  algorithm: FingerprintAlgorithm
): string
```

Synchronously compute a certificate fingerprint as a base64url-encoded hash of the DER-encoded certificate. **Requires Node.js** — throws in browser/Deno/Bun environments.

**Parameters:**
- `cert` — An `X509Certificate` object.
- `algorithm` — `'sha256'`, `'sha384'`, or `'sha512'`.

**Returns:** Base64url-encoded fingerprint string.

---

### `computeFingerprintAsync`

```typescript
async function computeFingerprintAsync(
  cert: X509Certificate,
  algorithm: FingerprintAlgorithm
): Promise<string>
```

Asynchronously compute a certificate fingerprint using the Web Crypto API. Cross-platform (Node.js, browser, Deno, Bun).

**Parameters:**
- `cert` — An `X509Certificate` object.
- `algorithm` — `'sha256'`, `'sha384'`, or `'sha512'`.

**Returns:** Base64url-encoded fingerprint string.

---

### `getKeyUsage`

```typescript
function getKeyUsage(cert: X509Certificate): {
  digitalSignature: boolean;
  keyAgreement: boolean;
} | null
```

Extract key usage flags from a certificate's Key Usage extension.

**Parameters:**
- `cert` — An `X509Certificate` object.

**Returns:** Object with `digitalSignature` and `keyAgreement` booleans, or `null` if no Key Usage extension is present.

---

## did-resolver Plugin

### `getDidX509Resolver`

```typescript
function getDidX509Resolver(): { x509: DIDResolver }
```

Returns a resolver object compatible with the `did-resolver` package's `Resolver` class.

The resolver expects an `x509chain` option (comma-separated base64url-encoded DER certificates) in the resolution options.

```typescript
import { Resolver } from 'did-resolver';
import { getDidX509Resolver } from '@didx509/core';

const resolver = new Resolver(getDidX509Resolver());
const result = await resolver.resolve('did:x509:0:sha256:...', {
  x509chain: 'der1,der2,...',
});

// result.didDocument — W3C DID Document or null
// result.didResolutionMetadata — contains error info if resolution failed
```

---

## Encoding Utilities

### `b64url`

```typescript
function b64url(data: Uint8Array): string
```

Base64url-encode bytes without padding.

**Parameters:**
- `data` — Input bytes.

**Returns:** Base64url-encoded string.

---

### `b64urlDecode`

```typescript
function b64urlDecode(str: string): Uint8Array
```

Base64url-decode a string (handles missing padding).

**Parameters:**
- `str` — Base64url-encoded string.

**Returns:** Decoded bytes as `Uint8Array`.

---

### `pctEncode`

```typescript
function pctEncode(data: string): string
```

Percent-encode a string per RFC 3986. Characters `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~` are passed through; all others are percent-encoded.

**Parameters:**
- `data` — Input string.

**Returns:** Percent-encoded string.

```typescript
pctEncode('CN=example.com'); // "CN%3Dexample.com"
```

---

### `pctDecode`

```typescript
function pctDecode(data: string): string
```

Percent-decode a string per RFC 3986.

**Parameters:**
- `data` — Percent-encoded string.

**Returns:** Decoded string.

---

### `parseNameString`

```typescript
function parseNameString(nameStr: string): CertificateName
```

Convert an X.509 name string (e.g. `"CN=example.com, O=Org"`) to a `CertificateName` object using RFC 4514 labels mapped to OID dotted strings.

**Parameters:**
- `nameStr` — Comma-separated `LABEL=value` pairs.

**Returns:** `CertificateName` object with OID keys.

```typescript
const name = parseNameString('CN=example.com, O=Acme Inc');
// { "2.5.4.3": "example.com", "2.5.4.10": "Acme Inc" }
```

---

### `oidToLabel`

```typescript
function oidToLabel(oid: string): string
```

Convert an OID dotted string to its RFC 4514 label. Returns the OID string itself if no mapping exists.

**Parameters:**
- `oid` — OID dotted string (e.g. `"2.5.4.3"`).

**Returns:** Label string (e.g. `"CN"`) or the original OID string.

---

## Types

### `DidDocument`

```typescript
interface DidDocument {
  '@context': string;
  id: string;
  verificationMethod: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
}
```

W3C DID Document. The `@context` is always `"https://www.w3.org/ns/cid/v1"` for did:x509.

---

### `VerificationMethod`

```typescript
interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: Record<string, unknown>;
}
```

DID Document verification method entry. The `type` is always `"JsonWebKey"` and `publicKeyJwk` contains the leaf certificate's public key.

---

### `DecodedCertificate`

```typescript
interface DecodedCertificate {
  fingerprint: CertificateFingerprint;
  issuer: CertificateName;
  subject: CertificateName;
  extensions: CertificateExtensions;
}
```

Decoded certificate representation matching the did:x509 JSON model.

---

### `CertificateFingerprint`

```typescript
interface CertificateFingerprint {
  sha256: string;
  sha384: string;
  sha512: string;
}
```

Certificate fingerprint hashes, each a base64url-encoded string.

---

### `CertificateName`

```typescript
interface CertificateName {
  [key: string]: string;
}
```

X.509 certificate name attributes. Keys are RFC 4514 labels (`CN`, `O`, `OU`, `C`, `ST`, `L`, `STREET`) or dotted OID strings.

---

### `CertificateExtensions`

```typescript
interface CertificateExtensions {
  eku?: string[];
  san?: SanEntry[];
  fulcio_issuer?: string;
}
```

Relevant X.509 extensions parsed from the certificate.

- `eku` — Extended Key Usage OIDs.
- `san` — Subject Alternative Name entries.
- `fulcio_issuer` — Fulcio issuer extension value (OID `1.3.6.1.4.1.57264.1.1`).

---

### `SanEntry`

```typescript
type SanEntry = [type: string, value: string | CertificateName];
```

Subject Alternative Name entry as a `[type, value]` tuple. Types include `"email"`, `"dns"`, `"uri"`, and `"dn"`.

---

### `ResolveOptions`

```typescript
interface ResolveOptions {
  skipValidityPeriodCheck?: boolean;
}
```

Options for DID resolution.

- `skipValidityPeriodCheck` — If `true`, skip certificate validity period checks. Useful for expired test certificates.

---

### `FingerprintAlgorithm`

```typescript
type FingerprintAlgorithm = 'sha256' | 'sha384' | 'sha512';
```

Supported fingerprint algorithm names.

---

### `PredicateName`

```typescript
type PredicateName = 'subject' | 'san' | 'eku' | 'fulcio-issuer';
```

Supported predicate names in did:x509 DIDs.

---

### `ParsedDid`

```typescript
interface ParsedDid {
  didDocumentId: string;
  did: string;
  caFingerprintAlgorithm: FingerprintAlgorithm;
  caFingerprint: string;
  predicates: [PredicateName, string][];
}
```

Parsed DID components from `parseDid()`.

- `didDocumentId` — The full DID string without fragment.
- `did` — The full DID string including fragment (if present).
- `caFingerprintAlgorithm` — The fingerprint algorithm (`sha256`, `sha384`, `sha512`).
- `caFingerprint` — The base64url-encoded CA fingerprint.
- `predicates` — Array of `[name, value]` tuples (e.g., `[["subject", "CN%3Dexample.com"]]`).
