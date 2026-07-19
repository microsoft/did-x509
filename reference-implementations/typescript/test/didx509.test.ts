// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import { resolveDidFromPem, convertChain } from '../src/didx509.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const TEST_DATA_DIR = resolve(import.meta.dirname, '../shared-test-data');
const MS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'ms-code-signing.pem');
const FULCIO_EMAIL_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-email.pem');
const FULCIO_GITHUB_ACTIONS_CHAIN_PATH = resolve(TEST_DATA_DIR, 'fulcio-github-actions.pem');

const msChainPem = readFileSync(MS_CHAIN_PATH, 'utf-8');
const fulcioEmailChainPem = readFileSync(FULCIO_EMAIL_CHAIN_PATH, 'utf-8');
const fulcioGithubActionsChainPem = readFileSync(FULCIO_GITHUB_ACTIONS_CHAIN_PATH, 'utf-8');

const BASE_DID =
  'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation';

function assertResolvedDidDocument(
  doc: Record<string, unknown>,
  expectedDid: string
) {
  expect(doc['@context']).toBe('https://www.w3.org/ns/cid/v1');
  expect(doc['id']).toBe(expectedDid);

  const verificationMethod = doc['verificationMethod'] as Array<Record<string, unknown>>;
  expect(verificationMethod).toHaveLength(1);
  expect(verificationMethod[0]['id']).toBe(`${expectedDid}#0`);
  expect(verificationMethod[0]['type']).toBe('JsonWebKey');
  expect(verificationMethod[0]['controller']).toBe(expectedDid);

  expect(doc['authentication']).toEqual([`${expectedDid}#0`]);
  expect(doc['assertionMethod']).toEqual([`${expectedDid}#0`]);
  expect(doc['keyAgreement']).toEqual([`${expectedDid}#0`]);
}

describe('did:x509 resolution', () => {
  // Ported from Python test_root_ca
  it('resolves with root CA fingerprint', async () => {
    const doc = await resolveDidFromPem(
      'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation',
      msChainPem,
      { skipValidityPeriodCheck: true }
    );
    assertResolvedDidDocument(doc, 'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation');
  });

  // Ported from Python test_intermediate_ca
  it('resolves with intermediate CA fingerprint', async () => {
    const doc = await resolveDidFromPem(
      'did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys::subject:CN:Microsoft%20Corporation',
      msChainPem,
      { skipValidityPeriodCheck: true }
    );
    assertResolvedDidDocument(doc, 'did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys::subject:CN:Microsoft%20Corporation');
  });

  // Ported from Python test_invalid_leaf_ca
  it('rejects leaf cert fingerprint', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:UXBZJ2K9iZ6KYBN7WzuRXxqz-3CB2nKpuhEYghJPDww::subject:CN:Microsoft%20Corporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_invalid_ca
  it('rejects nonexistent fingerprint', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:abc::CN:Microsoft%20Corporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_subject
  it('resolves with subject predicate', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  // Ported from Python test_subject_invalid_name
  it('rejects invalid subject value', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:MicrosoftCorporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_subject_duplicate_field
  it('rejects duplicate subject fields', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation:CN:Microsoft%20Corporation',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_multiple_policies
  it('resolves with multiple EKU policies', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.3.6.1.5.5.7.3.3::eku:1.3.6.1.4.1.311.10.3.21',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  // Ported from Python test_eku
  it('resolves with EKU predicate', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.3.6.1.5.5.7.3.3',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  // Ported from Python test_eku_invalid_value
  it('rejects invalid EKU OID', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.2.3',
        msChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_san
  it('resolves with SAN email predicate', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:email:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  // Ported from Python test_san_invalid_type
  it('rejects wrong SAN type', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:uri:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_san_invalid_value
  it('rejects wrong SAN value', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::email:bob%40example.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).rejects.toThrow();
  });

  // Ported from Python test_fulcio_issuer_with_email_san
  it('resolves with Fulcio issuer and email SAN', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:github.com%2Flogin%2Foauth::san:email:igarcia%40suse.com',
        fulcioEmailChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });

  // Ported from Python test_fulcio_issuer_with_uri_san
  it('resolves with Fulcio issuer and URI SAN', async () => {
    await expect(
      resolveDidFromPem(
        'did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:token.actions.githubusercontent.com::san:uri:https%3A%2F%2Fgithub.com%2Fbrendancassells%2Fmcw-continuous-delivery-lab-files%2F.github%2Fworkflows%2Ffabrikam-web.yml%40refs%2Fheads%2Fmain',
        fulcioGithubActionsChainPem,
        { skipValidityPeriodCheck: true }
      )
    ).resolves.toBeDefined();
  });
});

describe('DID URL handling', () => {
  // Ported from Python test_did_url_path_not_supported
  describe('rejects paths', () => {
    for (const suffix of ['/credentials', '/credentials#0', '/credentials?versionId=1#0']) {
      it(`rejects ${suffix}`, async () => {
        await expect(
          resolveDidFromPem(BASE_DID + suffix, msChainPem, { skipValidityPeriodCheck: true })
        ).rejects.toThrow('DID URL path is not supported');
      });
    }
  });

  // Ported from Python test_did_url_query_not_supported
  describe('rejects queries', () => {
    for (const suffix of ['?versionId=1', '?versionId=1#0', '?service=/credentials#0']) {
      it(`rejects ${suffix}`, async () => {
        await expect(
          resolveDidFromPem(BASE_DID + suffix, msChainPem, { skipValidityPeriodCheck: true })
        ).rejects.toThrow('DID URL query is not supported');
      });
    }
  });

  // Ported from Python test_did_url_fragment_produces_clean_document
  describe('accepts fragments', () => {
    for (const suffix of ['#0', '#0/credentials', '#0?versionId=1', '#0/credentials?versionId=1']) {
      it(`accepts ${suffix}`, async () => {
        const doc = await resolveDidFromPem(BASE_DID + suffix, msChainPem, { skipValidityPeriodCheck: true });
        assertResolvedDidDocument(doc, BASE_DID);
      });
    }
  });
});
