# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from didx509.didx509 import load_certificate_chain, resolve_did


def test_root_ca():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    resolve_did(
        r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation",
        chain,
        skip_validity_period_check=True,
    )


def test_intermediate_ca():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    resolve_did(
        r"did:x509:0:sha256:VtqHIq_ZQGb_4eRZVHOkhUiSuEOggn1T-32PSu7R4Ys::subject:CN:Microsoft%20Corporation",
        chain,
        skip_validity_period_check=True,
    )


def test_invalid_leaf_ca():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:UXBZJ2K9iZ6KYBN7WzuRXxqz-3CB2nKpuhEYghJPDww::subject:CN:Microsoft%20Corporation",
            chain,
            skip_validity_period_check=True,
        )


def test_invalid_ca():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:abc::CN:Microsoft%20Corporation",
            chain,
            skip_validity_period_check=True,
        )


def test_did_url_path_not_supported():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError, match="DID URL path is not supported"):
        resolve_did(
            r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation/credentials",
            chain,
            skip_validity_period_check=True,
        )


def test_did_url_fragment_produces_clean_document():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    base_did = r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation"
    doc = resolve_did(
        base_did + "#0",
        chain,
        skip_validity_period_check=True,
    )
    assert doc["id"] == base_did
    assert doc["verificationMethod"][0]["id"] == f"{base_did}#0"
    assert doc["verificationMethod"][0]["controller"] == base_did


def test_multiple_policies():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    resolve_did(
        r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.3.6.1.5.5.7.3.3::eku:1.3.6.1.4.1.311.10.3.21",
        chain,
        skip_validity_period_check=True,
    )


def test_subject():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    resolve_did(
        r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation",
        chain,
        skip_validity_period_check=True,
    )


def test_subject_invalid_name():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:MicrosoftCorporation",
            chain,
            skip_validity_period_check=True,
        )


def test_subject_duplicate_field():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation:CN:Microsoft%20Corporation",
            chain,
            skip_validity_period_check=True,
        )


def test_san():
    chain = load_certificate_chain("test-data/fulcio-email.pem")

    resolve_did(
        r"did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:email:igarcia%40suse.com",
        chain,
        skip_validity_period_check=True,
    )


def test_san_invalid_type():
    chain = load_certificate_chain("test-data/fulcio-email.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::san:uri:igarcia%40suse.com",
            chain,
            skip_validity_period_check=True,
        )


def test_san_invalid_value():
    chain = load_certificate_chain("test-data/fulcio-email.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::email:bob%40example.com",
            chain,
            skip_validity_period_check=True,
        )


def test_eku():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    resolve_did(
        r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.3.6.1.5.5.7.3.3",
        chain,
        skip_validity_period_check=True,
    )


def test_eku_invalid_value():
    chain = load_certificate_chain("test-data/ms-code-signing.pem")

    with pytest.raises(ValueError):
        resolve_did(
            r"did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::eku:1.2.3",
            chain,
            skip_validity_period_check=True,
        )


def test_fulcio_issuer_with_email_san():
    chain = load_certificate_chain("test-data/fulcio-email.pem")

    resolve_did(
        r"did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:github.com%2Flogin%2Foauth::san:email:igarcia%40suse.com",
        chain,
        skip_validity_period_check=True,
    )


def test_fulcio_issuer_with_uri_san():
    chain = load_certificate_chain("test-data/fulcio-github-actions.pem")

    resolve_did(
        r"did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio-issuer:token.actions.githubusercontent.com::san:uri:https%3A%2F%2Fgithub.com%2Fbrendancassells%2Fmcw-continuous-delivery-lab-files%2F.github%2Fworkflows%2Ffabrikam-web.yml%40refs%2Fheads%2Fmain",
        chain,
        skip_validity_period_check=True,
    )
