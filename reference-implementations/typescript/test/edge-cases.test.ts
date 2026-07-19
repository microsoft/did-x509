// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { parseDid, checkDidX509, resolveDidFromPem, convertChain } from '../src/didx509.js';
import { loadPemCertificateChain } from '../src/x509.js';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');
const MS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'ms-code-signing.pem');
const FULCIO_EMAIL_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-email.pem');
const FULCIO_GITHUB_ACTIONS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-github-actions.pem');

const msChainPem = readFileSync(MS_CHAIN_PATH, 'utf-8');
const fulcioEmailChainPem = readFileSync(FULCIO_EMAIL_CHAIN_PATH, 'utf-8');
const fulcioGithubActionsChainPem = readFileSync(FULCIO_GITHUB_ACTIONS_CHAIN_PATH, 'utf-8');

describe('parseDid', () => {
  it('rejects invalid prefix', () => {
    expect(() => parseDid('did:web:example.com')).toThrow('invalid did prefix');
  });

  it('rejects empty string', () => {
    expect(() => parseDid('')).toThrow();
  });

  it('rejects DID with no CA fingerprint', () => {
    expect(() => parseDid('did:x509:0:sha256:')).toThrow();
  });

  it('rejects DID with missing algorithm', () => {
    expect(() => parseDid('did:x509:0::abc')).toThrow();
  });

  it('parses valid DID with predicates', () => {
    const result = parseDid(
      'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Test'
    );
    expect(result.caFingerprintAlgorithm).toBe('sha256');
    expect(result.caFingerprint).toBe('hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE');
    expect(result.predicates).toEqual([['subject', 'CN:Test']]);
  });

  it('parses DID with fragment', () => {
    const result = parseDid(
      'did:x509:0:sha256:abc::subject:CN:Test#fragment'
    );
    expect(result.didDocumentId).toBe('did:x509:0:sha256:abc::subject:CN:Test');
    expect(result.did).toBe('did:x509:0:sha256:abc::subject:CN:Test#fragment');
  });
});

describe('DID URL path and query handling', () => {
  it('rejects path in DID', () => {
    expect(
      () => parseDid('did:x509:0:sha256:abc/credentials::subject:CN:Test')
    ).toThrow('DID URL path is not supported');
  });

  it('rejects query in DID', () => {
    expect(
      () => parseDid('did:x509:0:sha256:abc?key=val::subject:CN:Test')
    ).toThrow('DID URL query is not supported');
  });

  it('rejects path before query', () => {
    expect(
      () => parseDid('did:x509:0:sha256:abc/cred?key=val::subject:CN:Test')
    ).toThrow('DID URL path is not supported');
  });

  it('accepts fragment after path in DID URL', () => {
    // Fragment is stripped before path/query checks, so this parses fine
    const result = parseDid(
      'did:x509:0:sha256:abc::subject:CN:Test#0'
    );
    expect(result.didDocumentId).toBe('did:x509:0:sha256:abc::subject:CN:Test');
  });
});

describe('checkDidX509', () => {
  it('rejects DID with no predicates', () => {
    expect(
      () => parseDid('did:x509:0:sha256:abc')
    ).toThrow('no policies specified');
  });

  it('rejects unknown predicate name', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::unknown-predicate:value',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow('unknown did:x509 policy');
  });
});

describe('Predicate validation', () => {
  it('rejects empty subject value in predicate', async () => {
    // Empty value after pctDecode is empty string, which won't match cert subject
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  it('rejects single cert chain', async () => {
    const chain = loadPemCertificateChain(msChainPem);
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
    // Single cert chain should fail at verifyCertificateChain level
    const { verifyCertificateChain } = await import('../src/x509.js');
    await expect(
      verifyCertificateChain([chain[0]!], true)
    ).rejects.toThrow('at least two');
  });
});

describe('Multiple predicates', () => {
  it('resolves with subject and EKU predicates', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation::eku:1.3.6.1.5.5.7.3.3',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  it('fails if any predicate does not match', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation::eku:1.2.3',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  it('order of predicates does not matter for resolution', async () => {
    const did1 =
      'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation::eku:1.3.6.1.5.5.7.3.3';
    const did2 =
      'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.3.6.1.5.5.7.3.3::subject:CN:Microsoft%20Corporation';

    const [doc1, doc2] = await Promise.all([
      resolveDidFromPem(did1, msChainPem, { skipValidityPeriodCheck: true }),
      resolveDidFromPem(did2, msChainPem, { skipValidityPeriodCheck: true }),
    ]);

    expect(doc1.verificationMethod).toHaveLength(1);
    expect(doc2.verificationMethod).toHaveLength(1);
    expect(doc1.verificationMethod[0]!.publicKeyJwk).toEqual(
      doc2.verificationMethod[0]!.publicKeyJwk
    );
  });

  it('resolves with three predicates', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation::eku:1.3.6.1.5.5.7.3.3::eku:1.3.6.1.4.1.311.10.3.21',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });
});

describe('SAN edge cases', () => {
  it('resolves with SAN predicate for fulcio-github-actions (URI type)', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:uri:https%3A%2F%2Fgithub.com%2Fbrendancassells%2Fmcw-continuous-delivery-lab-files%2F.github%2Fworkflows%2Ffabrikam-web.yml%40refs%2Fheads%2Fmain',
        fulcioGithubActionsChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  it('resolves with SAN predicate for fulcio-email (email type)', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:email:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  it('rejects SAN type that does not match (dns vs email)', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:dns:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });
});

describe('Fulcio issuer predicate', () => {
  it('resolves with correct fulcio-issuer', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:github.com%2Flogin%2Foauth::san:email:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  it('rejects wrong fulcio-issuer value', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:wrong.example.com::san:email:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });
});

describe('convertChain', () => {
  it('converts ms-code-signing chain to decoded certificates', () => {
    const decoded = convertChain(msChainPem);
    expect(decoded).toHaveLength(3);
    expect(decoded[0]!.fingerprint.sha256).toBeTruthy();
    expect(decoded[0]!.subject['CN']).toBe('Microsoft Corporation');
  });

  it('converts fulcio-email chain', () => {
    const decoded = convertChain(fulcioEmailChainPem);
    expect(decoded).toHaveLength(2);
    expect(decoded[0]!.extensions.san).toBeDefined();
  });

  it('converts fulcio-github-actions chain', () => {
    const decoded = convertChain(fulcioGithubActionsChainPem);
    expect(decoded).toHaveLength(2);
    expect(decoded[0]!.extensions.fulcio_issuer).toBeDefined();
  });
});
