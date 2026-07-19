// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * did-resolver compatible plugin for did:x509.
 *
 * Usage:
 * ```ts
 * import { Resolver } from 'did-resolver';
 * import { getDidX509Resolver } from '@didx509/core';
 *
 * const resolver = new Resolver(getDidX509Resolver());
 * const result = await resolver.resolve(
 *   'did:x509:0:sha256:...',
 *   { x509chain: 'base64url_der1,base64url_der2,...' }
 * );
 * ```
 */

import { loadX509Chain, decodeCertificate, extractPublicKeyAsJwk, getKeyUsage } from './x509.js';
import { checkDidX509, parseDid } from './didx509.js';
import type { DidDocument, VerificationMethod } from './types.js';

const CID_CONTEXT = 'https://www.w3.org/ns/cid/v1';

/**
 * Minimal type for did-resolver's DIDResolutionOptions.
 * We avoid a hard dependency on did-resolver types.
 */
interface DidResolutionOptions {
  [key: string]: unknown;
}

/**
 * Minimal DID resolution result type.
 */
interface DidResolutionResult {
  didResolutionMetadata: Record<string, unknown>;
  didDocument: DidDocument | null;
  didDocumentMetadata: Record<string, unknown>;
}

/**
 * DID resolver function type (simplified).
 */
type DIDResolver = (
  did: string,
  parsed: { did: string; id: string; method: string; identifier: string },
  resolver: unknown,
  options: DidResolutionOptions
) => Promise<DidResolutionResult>;

/**
 * Returns a resolver object compatible with did-resolver's Resolver class.
 */
export function getDidX509Resolver(): { x509: DIDResolver } {
  return {
    x509: async (
      did: string,
      _parsed: unknown,
      _resolver: unknown,
      options: DidResolutionOptions
    ): Promise<DidResolutionResult> => {
      const x509chain = options['x509chain'] as string | undefined;

      if (!x509chain || typeof x509chain !== 'string') {
        return {
          didResolutionMetadata: {
            error: 'invalidDidResolutionOptions',
            message: 'x509chain resolution option is required',
          },
          didDocument: null,
          didDocumentMetadata: {},
        };
      }

      try {
        const chain = loadX509Chain(x509chain);
        const decodedChain = chain.map(c => decodeCertificate(c));
        const didDocumentId = checkDidX509(did, decodedChain);

        const leaf = chain[0]!;
        const publicKeyJwk = await extractPublicKeyAsJwk(leaf);

        const verificationMethod: VerificationMethod = {
          id: `${didDocumentId}#0`,
          type: 'JsonWebKey',
          controller: didDocumentId,
          publicKeyJwk,
        };

        const doc: DidDocument = {
          '@context': CID_CONTEXT,
          id: didDocumentId,
          verificationMethod: [verificationMethod],
        };

        const keyUsage = getKeyUsage(leaf);
        const includeAssertionMethod =
          keyUsage === null || keyUsage.digitalSignature;
        const includeKeyAgreement =
          keyUsage === null || keyUsage.keyAgreement;

        if (includeAssertionMethod) {
          doc.authentication = [`${didDocumentId}#0`];
          doc.assertionMethod = [`${didDocumentId}#0`];
        }
        if (includeKeyAgreement) {
          doc.keyAgreement = [`${didDocumentId}#0`];
        }

        return {
          didResolutionMetadata: { contentType: 'application/did+ld+json' },
          didDocument: doc,
          didDocumentMetadata: {},
        };
      } catch (error) {
        const message =
          error instanceof Error ? error.message : String(error);
        return {
          didResolutionMetadata: {
            error: 'notFound',
            message,
          },
          didDocument: null,
          didDocumentMetadata: {},
        };
      }
    },
  };
}
