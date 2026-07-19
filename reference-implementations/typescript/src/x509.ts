// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import {
  X509Certificate,
  SubjectAlternativeNameExtension,
  ExtendedKeyUsageExtension,
  KeyUsagesExtension,
  BasicConstraintsExtension,
  type GeneralNameType,
} from '@peculiar/x509';
import * as asn1js from 'asn1js';
import pkijs from 'pkijs';
import { b64url, b64urlDecode, oidToLabel } from './encoding.js';
import type {
  CertificateFingerprint,
  CertificateExtensions,
  CertificateName,
  DecodedCertificate,
  FingerprintAlgorithm,
} from './types.js';

/**
 * Fulcio issuer extension OID.
 */
const FULCIO_ISSUER_OID = '1.3.6.1.4.1.57264.1.1';

/**
 * Map @peculiar/x509 GeneralNameType to did:x509 SAN type names.
 */
function mapSanType(type: GeneralNameType): string {
  switch (type) {
    case 'email':
      return 'email';
    case 'dns':
      return 'dns';
    case 'url':
      return 'uri';
    case 'dn':
      return 'dn';
    default:
      return type;
  }
}

/**
 * Get the global Web Crypto instance.
 */
function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new Error(
    'Web Crypto API not available. Ensure crypto.subtle is accessible in your runtime.'
  );
}

/**
 * Get Node.js crypto for synchronous operations.
 */
function getNodeCrypto(): typeof import('node:crypto') | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('node:crypto');
  } catch {
    return null;
  }
}

/**
 * Extract TBSCertificate bytes from a DER-encoded certificate.
 * This uses pkijs + asn1js for proper ASN.1 parsing.
 */
function extractTbsCertificate(cert: X509Certificate): ArrayBuffer {
  const asn1 = asn1js.fromBER(cert.rawData);
  const pkijsCert = new pkijs.Certificate({ schema: asn1.result });
  return pkijsCert.tbs;
}

/**
 * Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
 * to raw r||s format (IEEE P1363) expected by Web Crypto.
 */
function derToRawEcdsaSignature(derSig: ArrayBuffer): ArrayBuffer {
  const asn1 = asn1js.fromBER(derSig);
  const seq = asn1.result;
  if (!(seq instanceof asn1js.Sequence)) {
    throw new Error('Invalid ECDSA signature: not a SEQUENCE');
  }

  const values = (seq.valueBlock as any).value;
  if (!values || values.length !== 2) {
    throw new Error('Invalid ECDSA signature: expected 2 integers');
  }

  // Get r and s as Uint8Array
  const rBlock = values[0] as asn1js.Integer;
  const sBlock = values[1] as asn1js.Integer;
  const r = new Uint8Array((rBlock.valueBlock as any).valueHexView);
  const s = new Uint8Array((sBlock.valueBlock as any).valueHexView);

  // Remove leading zeros ( ASN.1 integers may have a leading 0x00 for positive values with high bit set)
  const rClean = removeLeadingZeros(r);
  const sClean = removeLeadingZeros(s);

  // Both r and s must be exactly 32 bytes for P-256, 48 bytes for P-384
  // Determine the key size from the algorithm or use a fixed size
  const keySize = Math.max(rClean.length, sClean.length);
  const rPadded = padToLength(rClean, keySize);
  const sPadded = padToLength(sClean, keySize);

  // Concatenate r || s
  const raw = new ArrayBuffer(keySize * 2);
  const rawView = new Uint8Array(raw);
  rawView.set(rPadded, 0);
  rawView.set(sPadded, keySize);
  return raw;
}

function removeLeadingZeros(arr: Uint8Array): Uint8Array {
  let start = 0;
  while (start < arr.length - 1 && arr[start] === 0) {
    start++;
  }
  return arr.slice(start);
}

function padToLength(arr: Uint8Array, length: number): Uint8Array {
  if (arr.length === length) return arr;
  if (arr.length > length) return arr.slice(arr.length - length);
  const padded = new Uint8Array(length);
  padded.set(arr, length - arr.length);
  return padded;
}

/**
 * Compute a certificate fingerprint as a base64url-encoded hash of the DER-encoded certificate.
 */
export function computeFingerprint(
  cert: X509Certificate,
  algorithm: FingerprintAlgorithm
): string {
  const nodeCrypto = getNodeCrypto();
  if (nodeCrypto) {
    const hashAlg =
      algorithm === 'sha256'
        ? 'sha256'
        : algorithm === 'sha384'
          ? 'sha384'
          : 'sha512';
    const hash = nodeCrypto.createHash(hashAlg);
    hash.update(new Uint8Array(cert.rawData));
    return b64url(new Uint8Array(hash.digest()));
  }

  throw new Error(
    'Synchronous fingerprint computation requires Node.js. Use computeFingerprintAsync for browser environments.'
  );
}

/**
 * Async fingerprint computation using Web Crypto API.
 */
export async function computeFingerprintAsync(
  cert: X509Certificate,
  algorithm: FingerprintAlgorithm
): Promise<string> {
  const crypto = getWebCrypto();
  let hashAlg: string;
  switch (algorithm) {
    case 'sha256':
      hashAlg = 'SHA-256';
      break;
    case 'sha384':
      hashAlg = 'SHA-384';
      break;
    case 'sha512':
      hashAlg = 'SHA-512';
      break;
  }
  const hashBuffer = await crypto.subtle.digest(hashAlg, cert.rawData);
  return b64url(new Uint8Array(hashBuffer));
}

/**
 * Parse X.509 Name from @peculiar/x509 Name object's JSON representation.
 */
function parseNameAttributes(cert: X509Certificate, which: 'subject' | 'issuer'): CertificateName {
  const nameObj = which === 'subject' ? cert.subjectName : cert.issuerName;
  const json = nameObj.toJSON();
  const result: CertificateName = {};
  const seenOids = new Set<string>();

  for (const attr of json) {
    for (const [oid, values] of Object.entries(attr)) {
      if (seenOids.has(oid)) {
        throw new Error('duplicates not allowed');
      }
      seenOids.add(oid);

      const label = oidToLabel(oid);
      // Take the first value from the array
      const firstVal = Array.isArray(values) ? values[0] : values;
      if (typeof firstVal === 'string') {
        result[label] = firstVal;
      } else if (typeof firstVal === 'object' && firstVal !== null) {
        // Handle JsonAttributeObject (utf8String, printableString, etc.)
        const obj = firstVal as Record<string, string>;
        const strVal = obj['utf8String'] ?? obj['printableString'] ?? obj['ia5String'] ?? '';
        result[label] = strVal;
      }
    }
  }

  return result;
}

/**
 * Parse SAN extension into did:x509 JSON model format.
 */
function parseSanExtension(cert: X509Certificate): [string, string | CertificateName][] {
  const sanExt = cert.getExtension(SubjectAlternativeNameExtension);
  if (!sanExt) return [];

  const entries: [string, string | CertificateName][] = [];
  for (const name of sanExt.names.items) {
    const mappedType = mapSanType(name.type);
    entries.push([mappedType, name.value]);
  }

  return entries;
}

/**
 * Parse EKU extension into OID list.
 */
function parseEkuExtension(cert: X509Certificate): string[] | undefined {
  const ekuExt = cert.getExtension(ExtendedKeyUsageExtension);
  if (!ekuExt) return undefined;
  if (ekuExt.usages.length === 0) return undefined;
  return ekuExt.usages.map(u => String(u));
}

/**
 * Parse Fulcio issuer extension from raw extension data.
 */
function parseFulcioIssuerExtension(cert: X509Certificate): string | undefined {
  const ext = cert.getExtension(FULCIO_ISSUER_OID);
  if (!ext) return undefined;

  // The raw extension value is the DER-encoded OctetString containing the UTF-8 string
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(ext.value);
}

/**
 * Parse all relevant extensions from an X.509 certificate.
 */
function parseExtensions(cert: X509Certificate): CertificateExtensions {
  const extensions: CertificateExtensions = {};

  const san = parseSanExtension(cert);
  if (san.length > 0) {
    extensions.san = san;
  }

  const eku = parseEkuExtension(cert);
  if (eku) {
    extensions.eku = eku;
  }

  const fulcioIssuer = parseFulcioIssuerExtension(cert);
  if (fulcioIssuer) {
    extensions.fulcio_issuer = fulcioIssuer;
  }

  return extensions;
}

/**
 * Decode an X.509 certificate into the did:x509 JSON model representation.
 */
export function decodeCertificate(cert: X509Certificate): DecodedCertificate {
  return {
    fingerprint: {
      sha256: computeFingerprint(cert, 'sha256'),
      sha384: computeFingerprint(cert, 'sha384'),
      sha512: computeFingerprint(cert, 'sha512'),
    },
    issuer: parseNameAttributes(cert, 'issuer'),
    subject: parseNameAttributes(cert, 'subject'),
    extensions: parseExtensions(cert),
  };
}

/**
 * Load a PEM certificate chain from a PEM string.
 * Returns an array of X509Certificate objects, ordered leaf-first.
 */
export function loadPemCertificateChain(pem: string): X509Certificate[] {
  const separator = '-----END CERTIFICATE-----';
  const parts = pem.split(separator).filter(p => p.trim());
  const certs: X509Certificate[] = [];

  for (const part of parts) {
    const fullPem = (part + separator).trim();
    certs.push(new X509Certificate(fullPem));
  }

  return certs;
}

/**
 * Load certificate chain from DER-encoded buffers.
 */
export function loadDerCertificateChain(derChain: ArrayBuffer[]): X509Certificate[] {
  return derChain.map(der => new X509Certificate(new Uint8Array(der)));
}

/**
 * Load certificate chain from base64url-encoded DER strings (x509chain format).
 */
export function loadX509Chain(x509chain: string): X509Certificate[] {
  const parts = x509chain.split(',');
  return parts.map(part => {
    const derBytes = b64urlDecode(part.trim());
    // Convert Uint8Array to ArrayBuffer for @peculiar/x509
    const buffer = new ArrayBuffer(derBytes.byteLength);
    new Uint8Array(buffer).set(derBytes);
    return new X509Certificate(buffer);
  });
}

/**
 * Verify that certificate `cert` was issued by `issuer`.
 */
export async function verifyCertificateIssuedBy(
  cert: X509Certificate,
  issuer: X509Certificate
): Promise<void> {
  const crypto = getWebCrypto();

  // Check subject-issuer match
  const issuerSubject = issuer.subject;
  const certIssuer = cert.issuer;
  if (certIssuer !== issuerSubject) {
    throw new Error('Certificate issuer does not match subject of issuer certificate');
  }

  // Extract TBS bytes from the child certificate
  const tbsBytes = extractTbsCertificate(cert);

  // Export the issuer's public key
  const issuerPublicKey = await issuer.publicKey.export();

  // X.509 certificates store ECDSA signatures in DER format, but Web Crypto
  // expects raw r||s (IEEE P1363) format. Detect and convert if needed.
  let signatureBytes = cert.signature;
  const sigArray = new Uint8Array(cert.signature);
  if (sigArray[0] === 0x30) {
    // DER SEQUENCE tag - this is a DER-encoded ECDSA signature
    signatureBytes = derToRawEcdsaSignature(cert.signature);
  }

  // Verify the child certificate's signature against the issuer's public key
  const valid = await crypto.subtle.verify(
    cert.signatureAlgorithm,
    issuerPublicKey,
    signatureBytes,
    tbsBytes
  );

  if (!valid) {
    throw new Error('Certificate signature verification failed');
  }
}

/**
 * Verify a certificate chain (leaf first, root last).
 * Validates chain order, basic constraints, and optionally validity period.
 */
export async function verifyCertificateChain(
  chain: X509Certificate[],
  skipValidityPeriodCheck = false
): Promise<void> {
  if (chain.length < 2) {
    throw new Error('Certificate chain must have at least two certificates');
  }

  // Verify each certificate is issued by the next
  for (let i = 0; i < chain.length - 1; i++) {
    await verifyCertificateIssuedBy(chain[i]!, chain[i + 1]!);
  }

  // Verify basic constraints and validity period
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i]!;

    // Check basic constraints for non-leaf certificates
    if (i > 0) {
      const bcExt = cert.getExtension(BasicConstraintsExtension);
      if (bcExt) {
        if (!bcExt.ca) {
          throw new Error(`Certificate ${i} basic constraints: CA bit missing`);
        }
        if (
          bcExt.pathLength !== undefined &&
          bcExt.pathLength !== null &&
          bcExt.pathLength < i
        ) {
          throw new Error(
            `Certificate ${i} basic constraints: path length constraint violated`
          );
        }
      }
    }

    if (!skipValidityPeriodCheck) {
      const now = new Date();
      if (cert.notBefore > now || cert.notAfter < now) {
        throw new Error(`Certificate ${i} is not valid now`);
      }
    }
  }
}

/**
 * Extract the public key from a certificate as a JWK object.
 */
export async function extractPublicKeyAsJwk(
  cert: X509Certificate
): Promise<Record<string, unknown>> {
  const crypto = getWebCrypto();
  // Export the public key to a CryptoKey, then to JWK
  const cryptoKey = await cert.publicKey.export();
  const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);
  return jwk as Record<string, unknown>;
}

/**
 * Get key usage flags from a certificate.
 */
export function getKeyUsage(cert: X509Certificate): {
  digitalSignature: boolean;
  keyAgreement: boolean;
} | null {
  const kuExt = cert.getExtension(KeyUsagesExtension);
  if (!kuExt) return null;

  return {
    digitalSignature: !!(kuExt.usages & 1), // KeyUsageFlags.digitalSignature = 1
    keyAgreement: !!(kuExt.usages & 16), // KeyUsageFlags.keyAgreement = 16
  };
}
