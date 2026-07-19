// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * @didx509/core - TypeScript implementation of the did:x509 DID method.
 *
 * Bridges X.509 certificate infrastructure with W3C Decentralized Identifiers.
 */

// Core resolution
export {
  parseDid,
  checkDidX509,
  createDidDocument,
  resolveDid,
  resolveDidFromPem,
  convertChain,
} from './didx509.js';

// X.509 operations
export {
  loadPemCertificateChain,
  loadDerCertificateChain,
  loadX509Chain,
  decodeCertificate,
  verifyCertificateChain,
  extractPublicKeyAsJwk,
  computeFingerprint,
  computeFingerprintAsync,
  getKeyUsage,
} from './x509.js';

// Encoding utilities
export {
  b64url,
  b64urlDecode,
  pctEncode,
  pctDecode,
  parseNameString,
  oidToLabel,
} from './encoding.js';

// did-resolver plugin (optional)
export { getDidX509Resolver } from './did-resolver-plugin.js';

// Types
export type {
  CertificateFingerprint,
  CertificateName,
  CertificateExtensions,
  DecodedCertificate,
  DidDocument,
  VerificationMethod,
  ResolveOptions,
  FingerprintAlgorithm,
  PredicateName,
  ParsedDid,
} from './types.js';
