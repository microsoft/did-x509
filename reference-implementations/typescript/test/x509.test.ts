// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import {
  loadPemCertificateChain,
  decodeCertificate,
  verifyCertificateChain,
  extractPublicKeyAsJwk,
} from '../src/x509.js';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');
const MS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'ms-code-signing.pem');
const FULCIO_EMAIL_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-email.pem');
const FULCIO_GITHUB_ACTIONS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-github-actions.pem');

const msChainPem = readFileSync(MS_CHAIN_PATH, 'utf-8');
const fulcioEmailChainPem = readFileSync(FULCIO_EMAIL_CHAIN_PATH, 'utf-8');
const fulcioGithubActionsChainPem = readFileSync(FULCIO_GITHUB_ACTIONS_CHAIN_PATH, 'utf-8');

describe('loadPemCertificateChain', () => {
  it('parses ms-code-signing.pem into 3 certificates', () => {
    const chain = loadPemCertificateChain(msChainPem);
    expect(chain).toHaveLength(3);
  });

  it('parses fulcio-email.pem into 2 certificates', () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    expect(chain).toHaveLength(2);
  });

  it('parses fulcio-github-actions.pem into 2 certificates', () => {
    const chain = loadPemCertificateChain(fulcioGithubActionsChainPem);
    expect(chain).toHaveLength(2);
  });

  it('returns X509Certificate objects', () => {
    const chain = loadPemCertificateChain(msChainPem);
    expect(chain[0]!.subject).toBeDefined();
    expect(chain[0]!.issuer).toBeDefined();
    expect(chain[0]!.rawData).toBeDefined();
  });
});

describe('decodeCertificate', () => {
  it('computes sha256 fingerprint', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.fingerprint.sha256).toBeTruthy();
    expect(typeof decoded.fingerprint.sha256).toBe('string');
    // base64url sha256 is 43 chars
    expect(decoded.fingerprint.sha256.length).toBe(43);
  });

  it('computes sha384 fingerprint', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.fingerprint.sha384).toBeTruthy();
    expect(decoded.fingerprint.sha384.length).toBe(64);
  });

  it('computes sha512 fingerprint', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.fingerprint.sha512).toBeTruthy();
    expect(decoded.fingerprint.sha512.length).toBe(86);
  });

  it('parses subject name', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.subject['CN']).toBe('Microsoft Corporation');
    expect(decoded.subject['C']).toBe('US');
    expect(decoded.subject['O']).toBe('Microsoft Corporation');
  });

  it('parses issuer name', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.issuer['CN']).toBe('Microsoft Code Signing PCA 2011');
  });

  it('parses root CA subject', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const root = decodeCertificate(chain[chain.length - 1]!);
    expect(root.subject['CN']).toBe('Microsoft Root Certificate Authority 2011');
  });
});

describe('parseExtensions (via decodeCertificate)', () => {
  it('parses SAN email entries', () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    const decoded = decodeCertificate(chain[0]!);
    const sanEntries = decoded.extensions.san ?? [];
    const emailEntries = sanEntries.filter(([type]) => type === 'email');
    expect(emailEntries.length).toBeGreaterThan(0);
    expect(emailEntries[0]![1]).toContain('@');
  });

  it('parses SAN dn entries as only SAN type for ms-code-signing', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    const sanEntries = decoded.extensions.san ?? [];
    // ms-code-signing leaf cert has a DN SAN
    const dnEntries = sanEntries.filter(([type]) => type === 'dn');
    expect(dnEntries.length).toBeGreaterThan(0);
  });

  it('parses SAN uri entries', () => {
    const chain = loadPemCertificateChain(fulcioGithubActionsChainPem);
    const decoded = decodeCertificate(chain[0]!);
    const sanEntries = decoded.extensions.san ?? [];
    const uriEntries = sanEntries.filter(([type]) => type === 'uri');
    expect(uriEntries.length).toBeGreaterThan(0);
    expect(uriEntries[0]![1]).toContain('https://');
  });

  it('parses EKU OIDs', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.extensions.eku).toBeDefined();
    expect(decoded.extensions.eku!.length).toBeGreaterThan(0);
    // Code signing EKU
    expect(decoded.extensions.eku).toContain('1.3.6.1.5.5.7.3.3');
  });

  it('parses Fulcio issuer extension', () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.extensions.fulcio_issuer).toBeDefined();
    expect(decoded.extensions.fulcio_issuer).toContain('github.com');
  });

  it('has no basic constraints in extensions output', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.extensions).not.toHaveProperty('basic_constraints');
  });

  it('has no key usage in extensions output', () => {
    const chain = loadPemCertificateChain(msChainPem);
    const decoded = decodeCertificate(chain[0]!);
    expect(decoded.extensions).not.toHaveProperty('key_usage');
  });
});

describe('verifyCertificateChain', () => {
  it('passes for valid ms-code-signing chain', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    await expect(
      verifyCertificateChain(chain, true)
    ).resolves.toBeUndefined();
  });

  it('passes for valid fulcio-email chain', async () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    await expect(
      verifyCertificateChain(chain, true)
    ).resolves.toBeUndefined();
  });

  it('fails when chain is too short (single cert)', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    await expect(
      verifyCertificateChain([chain[0]!], true)
    ).rejects.toThrow('at least two certificates');
  });

  it('fails when issuer does not match (reversed chain)', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    // Reverse all but keep leaf at end — wrong order
    const reversed = [...chain].reverse();
    await expect(
      verifyCertificateChain(reversed, true)
    ).rejects.toThrow();
  });

  it('fails with validity period check on expired cert', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    // ms-code-signing.pem certs have expired (notAfter 2023-05-11)
    await expect(
      verifyCertificateChain(chain, false)
    ).rejects.toThrow();
  });

  it('passes with skipValidityPeriodCheck on expired cert', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    await expect(
      verifyCertificateChain(chain, true)
    ).resolves.toBeUndefined();
  });
});

describe('extractPublicKeyAsJwk', () => {
  it('exports EC key with correct kty and crv', async () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    const jwk = await extractPublicKeyAsJwk(chain[0]!);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
  });

  it('exports RSA key with correct kty', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    const jwk = await extractPublicKeyAsJwk(chain[0]!);
    expect(jwk.kty).toBe('RSA');
    expect(jwk.n).toBeDefined();
    expect(jwk.e).toBeDefined();
  });

  it('exports key with kid absent or string', async () => {
    const chain = loadPemCertificateChain(fulcioEmailChainPem);
    const jwk = await extractPublicKeyAsJwk(chain[0]!);
    if (jwk.kid) {
      expect(typeof jwk.kid).toBe('string');
    }
  });
});
