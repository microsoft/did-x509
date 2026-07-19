// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { pctDecode, pctEncode } from './encoding.js';
import {
  decodeCertificate,
  verifyCertificateChain,
  extractPublicKeyAsJwk,
  getKeyUsage,
  loadPemCertificateChain,
} from './x509.js';
import type {
  DidDocument,
  DecodedCertificate,
  ResolveOptions,
  VerificationMethod,
  CertificateFingerprint,
} from './types.js';
import type { X509Certificate } from '@peculiar/x509';

const DID_PREFIX = 'did:x509:0:';
const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';

/**
 * Parse a did:x509 DID string into its components.
 */
export function parseDid(did: string): {
  didDocumentId: string;
  did: string;
  caFingerprintAlgorithm: string;
  caFingerprint: string;
  predicates: [string, string][];
} {
  const didDocumentId = did.split('#', 1)[0]!;

  if (!didDocumentId.startsWith(DID_PREFIX)) {
    throw new Error('invalid did prefix');
  }

  const pathIndex = didDocumentId.indexOf('/');
  const queryIndex = didDocumentId.indexOf('?');

  if (pathIndex !== -1 && (queryIndex === -1 || pathIndex < queryIndex)) {
    throw new Error('DID URL path is not supported');
  }
  if (queryIndex !== -1) {
    throw new Error('DID URL query is not supported');
  }

  const rest = didDocumentId.substring(DID_PREFIX.length);
  const parts = rest.split('::');

  const [caFingerprintAlgorithm, caFingerprint] = parts[0]!.split(':');

  if (!caFingerprintAlgorithm || !caFingerprint) {
    throw new Error('invalid DID format: missing CA fingerprint algorithm or value');
  }

  const predicates: [string, string][] = [];
  for (let i = 1; i < parts.length; i++) {
    const colonIndex = parts[i]!.indexOf(':');
    if (colonIndex === -1) {
      throw new Error(`invalid predicate: ${parts[i]}`);
    }
    const name = parts[i]!.substring(0, colonIndex);
    const value = parts[i]!.substring(colonIndex + 1);
    predicates.push([name, value]);
  }

  if (predicates.length === 0) {
    throw new Error('no policies specified');
  }

  return {
    didDocumentId,
    did,
    caFingerprintAlgorithm,
    caFingerprint,
    predicates,
  };
}

/**
 * Validate a did:x509 DID against a decoded certificate chain.
 */
export function checkDidX509(
  did: string,
  decodedChain: DecodedCertificate[]
): string {
  const parsed = parseDid(did);
  const leaf = decodedChain[0]!;

  // Validate CA fingerprint matches a non-leaf certificate
  const expectedFingerprints = decodedChain.slice(1).map(c => {
    const fp = c.fingerprint[parsed.caFingerprintAlgorithm as keyof CertificateFingerprint];
    if (!fp) {
      throw new Error(
        `unsupported fingerprint algorithm: ${parsed.caFingerprintAlgorithm}`
      );
    }
    return fp;
  });

  if (!expectedFingerprints.includes(parsed.caFingerprint)) {
    throw new Error(
      `invalid CA fingerprint, expected one of: ${expectedFingerprints.join(', ')}`
    );
  }

  // Validate each predicate
  for (const [name, value] of parsed.predicates) {
    switch (name) {
      case 'subject':
        validateSubjectPredicate(value, leaf.subject);
        break;
      case 'san':
        validateSanPredicate(value, leaf.extensions.san ?? []);
        break;
      case 'eku':
        validateEkuPredicate(value, leaf.extensions.eku ?? []);
        break;
      case 'fulcio-issuer':
        validateFulcioIssuerPredicate(value, leaf.extensions.fulcio_issuer);
        break;
      default:
        throw new Error(`unknown did:x509 policy: ${name}`);
    }
  }

  return parsed.didDocumentId;
}

/**
 * Validate the subject predicate against leaf certificate subject.
 */
function validateSubjectPredicate(
  value: string,
  subject: Record<string, string>
): void {
  const parts = value.split(':');
  if (!parts || parts.length % 2 !== 0) {
    throw new Error('key-value pairs required');
  }

  const fields: [string, string][] = [];
  for (let i = 0; i < parts.length; i += 2) {
    fields.push([parts[i]!, parts[i + 1]!]);
  }

  if (fields.length !== new Set(fields.map(([k]) => k)).size) {
    throw new Error('duplicate subject fields');
  }

  for (const [key, encodedValue] of fields) {
    if (!(key in subject)) {
      throw new Error(`invalid subject key: ${key}`);
    }
    const decodedValue = pctDecode(encodedValue);
    const expectedValue = subject[key]!;
    if (decodedValue !== expectedValue) {
      throw new Error(
        `invalid subject value: ${key} = ${pctEncode(decodedValue)}, expected: ${pctEncode(expectedValue)}`
      );
    }
  }
}

/**
 * Validate the SAN predicate against leaf certificate SANs.
 */
function validateSanPredicate(
  value: string,
  sans: [string, string | Record<string, string>][]
): void {
  const parts = value.split(':');
  if (parts.length !== 2) {
    throw new Error('exactly one SAN type and value required');
  }

  const sanType = parts[0]!;
  const sanValue = pctDecode(parts[1]!);
  const san: [string, string | Record<string, string>] = [sanType, sanValue];

  const found = sans.some(
    s => s[0] === san[0] && JSON.stringify(s[1]) === JSON.stringify(san[1])
  );

  if (!found) {
    throw new Error(
      `invalid SAN: ${JSON.stringify(san)}, expected one of: ${JSON.stringify(sans)}`
    );
  }
}

/**
 * Validate the EKU predicate against leaf certificate EKUs.
 */
function validateEkuPredicate(value: string, ekus: string[]): void {
  if (ekus.length === 0) {
    throw new Error('no EKU extension in certificate');
  }
  if (!ekus.includes(value)) {
    throw new Error(
      `invalid EKU: ${value}, expected one of: ${ekus.join(', ')}`
    );
  }
}

/**
 * Validate the fulcio-issuer predicate against leaf certificate Fulcio issuer extension.
 */
function validateFulcioIssuerPredicate(
  value: string,
  fulcioIssuer: string | undefined
): void {
  if (!fulcioIssuer) {
    throw new Error('no Fulcio issuer extension in certificate');
  }
  const expected = 'https://' + pctDecode(value);
  if (expected !== fulcioIssuer) {
    throw new Error(
      `invalid Fulcio issuer: ${pctEncode(expected)}, expected: ${pctEncode(fulcioIssuer)}`
    );
  }
}

/**
 * Create a W3C DID Document from a DID and certificate chain.
 */
export function createDidDocument(
  did: string,
  chain: X509Certificate[]
): Promise<DidDocument> {
  return createDidDocumentInternal(did, chain);
}

async function createDidDocumentInternal(
  did: string,
  chain: X509Certificate[]
): Promise<DidDocument> {
  const leaf = chain[0]!;
  const publicKeyJwk = await extractPublicKeyAsJwk(leaf);

  const verificationMethod: VerificationMethod = {
    id: `${did}#0`,
    type: 'JsonWebKey',
    controller: did,
    publicKeyJwk,
  };

  const doc: DidDocument = {
    '@context': CID_CONTEXT,
    id: did,
    verificationMethod: [verificationMethod],
  };

  const keyUsage = getKeyUsage(leaf);

  const includeAssertionMethod =
    keyUsage === null || keyUsage.digitalSignature;
  const includeKeyAgreement = keyUsage === null || keyUsage.keyAgreement;

  if (includeAssertionMethod) {
    doc.authentication = [`${did}#0`];
    doc.assertionMethod = [`${did}#0`];
  }
  if (includeKeyAgreement) {
    doc.keyAgreement = [`${did}#0`];
  }

  if (!includeAssertionMethod && !includeKeyAgreement) {
    throw new Error(
      'leaf certificate key usage must include digital signature or key agreement'
    );
  }

  return doc;
}

/**
 * Resolve a did:x509 DID with a PEM certificate chain string.
 */
export async function resolveDid(
  did: string,
  chain: X509Certificate[],
  options: ResolveOptions = {}
): Promise<DidDocument> {
  await verifyCertificateChain(chain, options.skipValidityPeriodCheck);

  const decodedChain = chain.map(c => decodeCertificate(c));
  const didDocumentId = checkDidX509(did, decodedChain);

  const doc = await createDidDocument(didDocumentId, chain);
  return doc;
}

/**
 * Resolve a did:x509 DID with a PEM certificate chain string.
 */
export async function resolveDidFromPem(
  did: string,
  pemChain: string,
  options: ResolveOptions = {}
): Promise<DidDocument> {
  const chain = loadPemCertificateChain(pemChain);
  return resolveDid(did, chain, options);
}

/**
 * Convert a PEM certificate chain to the did:x509 JSON model.
 */
export function convertChain(pemChain: string): DecodedCertificate[] {
  const chain = loadPemCertificateChain(pemChain);
  return chain.map(c => decodeCertificate(c));
}
