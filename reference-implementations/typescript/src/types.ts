// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * Certificate fingerprint hashes keyed by algorithm name.
 */
export interface CertificateFingerprint {
  sha256: string;
  sha384: string;
  sha512: string;
}

/**
 * X.509 certificate name attributes.
 * Keys are RFC 4514 labels (CN, O, OU, C, ST, L, STREET) or dotted OID strings.
 */
export interface CertificateName {
  [key: string]: string;
}

/**
 * Subject Alternative Name entry as a [type, value] tuple.
 * Types: "email", "dns", "uri", "dn"
 */
export type SanEntry = [type: string, value: string | CertificateName];

/**
 * Relevant X.509 extensions parsed from the certificate.
 */
export interface CertificateExtensions {
  eku?: string[];
  san?: SanEntry[];
  fulcio_issuer?: string;
}

/**
 * Decoded certificate representation matching the did:x509 JSON model.
 */
export interface DecodedCertificate {
  fingerprint: CertificateFingerprint;
  issuer: CertificateName;
  subject: CertificateName;
  extensions: CertificateExtensions;
}

/**
 * DID Document verification method.
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: Record<string, unknown>;
}

/**
 * W3C DID Document.
 */
export interface DidDocument {
  '@context': string;
  id: string;
  verificationMethod: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
}

/**
 * Options for DID resolution.
 */
export interface ResolveOptions {
  skipValidityPeriodCheck?: boolean;
}

/**
 * Supported fingerprint algorithm names.
 */
export type FingerprintAlgorithm = 'sha256' | 'sha384' | 'sha512';

/**
 * Supported predicate names in did:x509 DIDs.
 */
export type PredicateName = 'subject' | 'san' | 'eku' | 'fulcio-issuer';

/**
 * Parsed DID components.
 */
export interface ParsedDid {
  /** The full DID string (without fragment). */
  didDocumentId: string;
  /** The full DID string including fragment (if present). */
  did: string;
  /** The fingerprint algorithm. */
  caFingerprintAlgorithm: FingerprintAlgorithm;
  /** The base64url-encoded CA fingerprint. */
  caFingerprint: string;
  /** Parsed predicates as [name, value] tuples. */
  predicates: [PredicateName, string][];
}
