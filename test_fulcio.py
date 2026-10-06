# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from didx509.der import decode_der_utf8_string
from didx509.didx509 import (
    FULCIO_EXTENSION_FIELDS,
    FULCIO_ISSUER_OID,
    SAN_OTHERNAME_DECODERS,
    check_did_x509,
    cli_convert,
    cli_resolve,
    decode_certificate,
    load_certificate_chain,
    pctencode,
    resolve_did,
)
from test_san_othername import (
    INVALID_DER_PARAMS,
    OTHERNAME_OID,
    der_value,
    did_for,
    make_chain,
    othername,
)
from test_vectors import TEST_VECTORS, load_vector_chain


FIXTURE_DIR = Path(__file__).parent / "test-data" / "fulcio-issuer-v2"
MANIFEST = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
FIELD_OIDS = MANIFEST["fulcio_oids"]
SAMPLES = {sample["id"]: sample for sample in MANIFEST["samples"]}
FULL_SAMPLE_ID = "pydantic-ai-2.54.0"
SIGSTORE_SAMPLE_ID = "sigstore-js-2026-08-04"
LEGACY_ISSUER = "https://legacy.example.com"
V2_ISSUER = "https://v2.example.com"
INVALID_PERCENT_UTF8 = [
    "%FF", "%FE", "%80", "%C3", "%C0%AF", "%ED%A0%80", "%F4%90%80%80",
    "%F0%9F", "%EF%BF", "%FF%EF%BF%BD",
]


def raw_extension(oid, payload, critical=False):
    return x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), payload), critical


def fulcio_extension(field, value, critical=False):
    return raw_extension(
        FIELD_OIDS[field], der_value(0x0C, value.encode("utf-8")), critical
    )


def legacy_extension(value=LEGACY_ISSUER, critical=False):
    return raw_extension(FULCIO_ISSUER_OID, value.encode("utf-8"), critical)


def selector(field, value):
    return f"fulcio:{field}:{pctencode(value)}"


@pytest.fixture(scope="module")
def full_fields_chain():
    return load_certificate_chain(FIXTURE_DIR / SAMPLES[FULL_SAMPLE_ID]["chain"])


@pytest.fixture(scope="module")
def sigstore_chain():
    return load_certificate_chain(FIXTURE_DIR / SAMPLES[SIGSTORE_SAMPLE_ID]["chain"])


@pytest.fixture(
    scope="module", params=MANIFEST["samples"], ids=lambda sample: sample["id"]
)
def real_sample(request):
    sample = request.param
    return sample, load_certificate_chain(FIXTURE_DIR / sample["chain"])


def test_standalone_registry_is_closed_and_separate_from_othername():
    assert FULCIO_EXTENSION_FIELDS == {
        oid: field for field, oid in FIELD_OIDS.items()
    }
    assert len(FULCIO_EXTENSION_FIELDS) == 17
    assert SAN_OTHERNAME_DECODERS == {OTHERNAME_OID: decode_der_utf8_string}
    assert not set(FULCIO_EXTENSION_FIELDS) & set(SAN_OTHERNAME_DECODERS)
    assert FULCIO_ISSUER_OID not in FULCIO_EXTENSION_FIELDS


@pytest.mark.parametrize("sample_id,vector_prefix", [
    (FULL_SAMPLE_ID, "fulcio-selector-real-pydantic-ai"),
    (SIGSTORE_SAMPLE_ID, "fulcio-selector-real-sigstore-js"),
])
def test_shared_vectors_cover_every_present_field_on_the_real_chains(
    sample_id, vector_prefix
):
    vectors = {vector["id"]: vector for vector in TEST_VECTORS}
    sample = SAMPLES[sample_id]
    for field, value in sample["fulcio"].items():
        vector = vectors[f"{vector_prefix}-{field}"]
        assert "document" in vector["output"]
        assert vector["input"]["did"].endswith(f"::{selector(field, value)}")
        assert [
            cert.fingerprint(hashes.SHA256()).hex() for cert in load_vector_chain(vector)
        ] == sample["certificate_sha256"]


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector["id"])
        for vector in TEST_VECTORS
        if vector["id"].startswith("fulcio-selector-")
        and not vector["id"].startswith("fulcio-selector-real-")
    ],
)
def test_synthetic_shared_vectors_are_fully_signed_independently(vector):
    chain = load_vector_chain(vector)
    assert len(chain) == 2
    for certificate, issuer in [(chain[0], chain[1]), (chain[1], chain[1])]:
        key = issuer.public_key()
        assert isinstance(key, ed25519.Ed25519PublicKey)
        key.verify(certificate.signature, certificate.tbs_certificate_bytes)


def test_real_mapping_matches_manifest_without_changing_certificate_bytes(real_sample):
    sample, chain = real_sample
    assert [
        certificate.fingerprint(hashes.SHA256()).hex() for certificate in chain
    ] == sample["certificate_sha256"]
    assert chain[0].not_valid_before_utc.isoformat() == sample["not_before"]
    assert chain[0].not_valid_after_utc.isoformat() == sample["not_after"]
    extensions = decode_certificate(chain[0])["extensions"]
    assert extensions["fulcio_issuer"] == sample["fulcio_issuer"]
    assert extensions["san"] == [sample["san"]]
    if sample["fulcio"]:
        assert extensions["fulcio"] == sample["fulcio"]
    else:
        assert "fulcio" not in extensions

    suffix = sample["fulcio_issuer"][len("https://"):]
    san_type, san_value = sample["san"]
    did = did_for(
        chain, f"fulcio-issuer:{pctencode(suffix)}::san:{san_type}:{pctencode(san_value)}"
    )
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("field", FIELD_OIDS)
def test_every_selector_resolves_against_unchanged_production_chain(full_fields_chain, field):
    value = SAMPLES[FULL_SAMPLE_ID]["fulcio"][field]
    did = did_for(full_fields_chain, selector(field, value))
    document = resolve_did(did, full_fields_chain)
    assert set(document) == {
        "@context", "id", "verificationMethod", "authentication", "assertionMethod",
    }
    assert document["@context"] == "https://www.w3.org/ns/cid/v1"
    assert document["id"] == did
    verification_method = document["verificationMethod"][0]
    assert verification_method["id"] == f"{did}#0"
    assert verification_method["controller"] == did
    assert verification_method["type"] == "JsonWebKey"
    assert verification_method["publicKeyJwk"]["kty"] == "EC"
    assert document["authentication"] == document["assertionMethod"] == [f"{did}#0"]


def test_all_seventeen_real_selectors_and_existing_predicates_are_anded(full_fields_chain):
    sample = SAMPLES[FULL_SAMPLE_ID]
    predicates = [selector(field, value) for field, value in sample["fulcio"].items()]
    predicates += [
        "fulcio-issuer:token.actions.githubusercontent.com",
        f"san:uri:{pctencode(sample['san'][1])}",
        selector("deployment-environment", sample["fulcio"]["deployment-environment"]),
    ]
    did = did_for(full_fields_chain, "::".join(predicates))
    assert resolve_did(did, full_fields_chain)["id"] == did
    with pytest.raises(ValueError, match="Fulcio predicate does not match"):
        resolve_did(f"{did}::fulcio:deployment-environment:wrong", full_fields_chain)


@pytest.mark.parametrize("field", [
    field for field in FIELD_OIDS if field != "deployment-environment"
])
def test_every_present_sigstore_js_field_resolves_including_token_subject(sigstore_chain, field):
    value = SAMPLES[SIGSTORE_SAMPLE_ID]["fulcio"][field]
    did = did_for(sigstore_chain, selector(field, value))
    assert resolve_did(did, sigstore_chain)["id"] == did


def test_refreshed_fixture_profiles_have_the_requested_optional_fields(
    full_fields_chain, sigstore_chain
):
    full_fields = decode_certificate(full_fields_chain[0])["extensions"]["fulcio"]
    assert set(full_fields) == set(FIELD_OIDS)
    assert full_fields["deployment-environment"] == "release"
    assert full_fields["token-subject"] == "repo:pydantic/pydantic-ai:environment:release"
    sigstore_fields = decode_certificate(sigstore_chain[0])["extensions"]["fulcio"]
    assert set(sigstore_fields) == set(FIELD_OIDS) - {"deployment-environment"}
    assert sigstore_fields["token-subject"] == "repo:sigstore/sigstore-js:ref:refs/heads/main"


def test_missing_deployment_environment_fails_on_real_sigstore_js_chain(sigstore_chain):
    field = "deployment-environment"
    value = SAMPLES[FULL_SAMPLE_ID]["fulcio"][field]
    with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
        resolve_did(did_for(sigstore_chain, selector(field, value)), sigstore_chain)


def test_missing_token_subject_fails_on_signed_synthetic_chain():
    chain = make_chain(extra_extensions=[
        fulcio_extension("issuer", V2_ISSUER),
        fulcio_extension("deployment-environment", "release"),
    ])
    predicate = selector("issuer", V2_ISSUER) + "::fulcio:deployment-environment:release"
    assert resolve_did(did_for(chain, predicate), chain)
    with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
        resolve_did(did_for(chain, predicate + "::fulcio:token-subject:alice"), chain)


@pytest.mark.parametrize("field", FIELD_OIDS)
def test_legacy_only_real_chain_does_not_supply_new_fields(field):
    chain = load_certificate_chain(FIXTURE_DIR / SAMPLES["legacy-staging"]["chain"])
    with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
        resolve_did(did_for(chain, selector(field, "opaque")), chain)


def test_production_and_staging_anchors_remain_distinct(full_fields_chain):
    staging = load_certificate_chain(FIXTURE_DIR / SAMPLES["legacy-staging"]["chain"])
    assert full_fields_chain[-1].fingerprint(hashes.SHA256()) != staging[-1].fingerprint(
        hashes.SHA256()
    )
    for expected, supplied in [(full_fields_chain, staging), (staging, full_fields_chain)]:
        did = did_for(expected, "fulcio-issuer:token.actions.githubusercontent.com")
        with pytest.raises(ValueError, match="CA fingerprint does not match"):
            check_did_x509(did, supplied)
        mixed = supplied[:-1] + expected[-1:]
        with pytest.raises(ValueError, match="Certificate chain verification failed"):
            resolve_did(did, mixed)


@pytest.mark.parametrize("field", FIELD_OIDS)
def test_one_present_field_does_not_require_any_other_field(field):
    value = f"opaque:{field}%/caf\u00e9"
    chain = make_chain(extra_extensions=[fulcio_extension(field, value)])
    assert decode_certificate(chain[0])["extensions"]["fulcio"] == {field: value}
    did = did_for(chain, selector(field, value))
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("field", FIELD_OIDS)
def test_non_leaf_fields_cannot_supply_leaf_matches(field):
    chain = make_chain(root_extensions=[fulcio_extension(field, "opaque")])
    assert decode_certificate(chain[-1])["extensions"]["fulcio"] == {field: "opaque"}
    with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
        resolve_did(did_for(chain, selector(field, "opaque")), chain)


@pytest.mark.parametrize("legacy,v2", [
    (LEGACY_ISSUER, None), (None, V2_ISSUER),
    (LEGACY_ISSUER, LEGACY_ISSUER), (LEGACY_ISSUER, V2_ISSUER),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_legacy_and_v2_are_independent_without_fallback_or_agreement(legacy, v2, reverse):
    extensions = []
    if legacy is not None:
        extensions.append(legacy_extension(legacy))
    if v2 is not None:
        extensions.append(fulcio_extension("issuer", v2))
    if reverse:
        extensions.reverse()
    chain = make_chain(extra_extensions=extensions)
    mapped = decode_certificate(chain[0])["extensions"]
    old_predicate = "fulcio-issuer:legacy.example.com"
    new_predicate = selector("issuer", v2 or V2_ISSUER)
    old_did, new_did = [did_for(chain, p) for p in [old_predicate, new_predicate]]
    if legacy is None:
        assert "fulcio_issuer" not in mapped
        with pytest.raises(ValueError, match="does not contain a Fulcio issuer extension"):
            resolve_did(old_did, chain)
    else:
        assert mapped["fulcio_issuer"] == legacy
        assert resolve_did(old_did, chain)["id"] == old_did
    if v2 is None:
        assert "fulcio" not in mapped
        with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
            resolve_did(new_did, chain)
    else:
        assert mapped["fulcio"] == {"issuer": v2}
        assert resolve_did(new_did, chain)["id"] == new_did
        if legacy != v2:
            suffix = v2[len("https://"):]
            with pytest.raises(ValueError, match="Fulcio issuer"):
                resolve_did(did_for(chain, f"fulcio-issuer:{pctencode(suffix)}"), chain)
    if legacy is not None and v2 is not None:
        did = did_for(chain, f"{old_predicate}::{new_predicate}")
        assert resolve_did(did, chain)["id"] == did
        assert old_did != new_did
        assert resolve_did(old_did, chain)["verificationMethod"][0]["publicKeyJwk"] == (
            resolve_did(new_did, chain)["verificationMethod"][0]["publicKeyJwk"]
        )
        if legacy != v2:
            with pytest.raises(ValueError, match="Fulcio predicate does not match"):
                resolve_did(did_for(chain, selector("issuer", legacy)), chain)


def test_legacy_payload_remains_raw_utf8_not_der():
    payload = der_value(0x0C, LEGACY_ISSUER.encode())
    chain = make_chain(extra_extensions=[
        raw_extension(FULCIO_ISSUER_OID, payload), fulcio_extension("issuer", V2_ISSUER),
    ])
    extensions = decode_certificate(chain[0])["extensions"]
    assert extensions["fulcio_issuer"] == payload.decode("utf-8")
    assert extensions["fulcio"] == {"issuer": V2_ISSUER}
    did = did_for(chain, selector("issuer", V2_ISSUER))
    assert resolve_did(did, chain)["id"] == did
    with pytest.raises(ValueError, match="Fulcio issuer predicate does not match"):
        resolve_did(did_for(chain, "fulcio-issuer:legacy.example.com"), chain)


def test_legacy_invalid_utf8_still_fails_eagerly():
    chain = make_chain(extra_extensions=[
        raw_extension(FULCIO_ISSUER_OID, b"\xff"), fulcio_extension("issuer", V2_ISSUER),
    ])
    with pytest.raises(ValueError, match="utf-8"):
        decode_certificate(chain[0])
    with pytest.raises(ValueError, match="utf-8"):
        resolve_did(did_for(chain, selector("issuer", V2_ISSUER)), chain)


@pytest.mark.parametrize("reverse", [False, True])
def test_all_fields_mapping_and_matching_are_extension_order_independent(reverse):
    values = {
        field: f"opaque:{index}%/value"
        for index, field in enumerate(FIELD_OIDS, start=8)
    }
    extensions = [legacy_extension()] + [
        fulcio_extension(field, value) for field, value in values.items()
    ]
    if reverse:
        extensions.reverse()
    chain = make_chain([othername("alice!example.com")], extra_extensions=extensions)
    mapped = decode_certificate(chain[0])["extensions"]
    assert mapped["fulcio"] == values
    assert mapped["fulcio_issuer"] == LEGACY_ISSUER
    predicates = [selector(field, value) for field, value in values.items()]
    predicates += [
        "fulcio-issuer:legacy.example.com",
        f"san:othername:{OTHERNAME_OID}:alice%21example.com",
    ]
    did = did_for(chain, "::".join(predicates))
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("encoded,message", INVALID_DER_PARAMS)
@pytest.mark.parametrize("field", ["issuer", "token-subject"])
@pytest.mark.parametrize("location", ["leaf", "root"])
def test_strict_der_fails_eagerly_even_for_unselected_extensions(
    encoded, message, field, location
):
    bad = raw_extension(FIELD_OIDS[field], encoded)
    leaf_extensions = [
        legacy_extension(), fulcio_extension("runner-environment", "opaque")
    ]
    chain = make_chain(
        [othername("alice!example.com")],
        extra_extensions=leaf_extensions + ([bad] if location == "leaf" else []),
        root_extensions=[bad] if location == "root" else [],
    )
    with pytest.raises(ValueError) as error:
        decode_certificate(chain[0] if location == "leaf" else chain[-1])
    assert str(error.value) == message
    for predicate in [
        selector(field, "opaque"), "subject:CN:Leaf",
        "fulcio-issuer:legacy.example.com", "fulcio:runner-environment:opaque",
        f"san:othername:{OTHERNAME_OID}:alice%21example.com",
    ]:
        with pytest.raises(ValueError) as error:
            resolve_did(did_for(chain, predicate), chain)
        assert str(error.value) == message


@pytest.mark.parametrize("field", FIELD_OIDS)
def test_every_registered_extension_uses_the_strict_der_decoder(field):
    chain = make_chain(extra_extensions=[
        raw_extension(FIELD_OIDS[field], der_value(0x16, b"opaque"))
    ])
    with pytest.raises(ValueError, match="not a primitive DER UTF8String"):
        decode_certificate(chain[0])
    with pytest.raises(ValueError, match="not a primitive DER UTF8String"):
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)


@pytest.mark.parametrize("value", [
    "", "\ufffd", "\x00", "a" * 127, "a" * 128, "a" * 255, "a" * 256,
    "\u00e9" * 64,
], ids=["empty", "replacement", "nul", "127", "128", "255", "256", "multibyte-128"])
def test_empty_and_long_der_strings_are_preserved_without_wildcards(value):
    chain = make_chain(extra_extensions=[fulcio_extension("issuer", value)])
    assert decode_certificate(chain[0])["extensions"]["fulcio"] == {"issuer": value}
    if value:
        did = did_for(chain, selector("issuer", value))
        assert resolve_did(did, chain)["id"] == did
    else:
        assert resolve_did(did_for(chain, "subject:CN:Leaf"), chain)
        with pytest.raises(ValueError, match="invalid predicate value"):
            resolve_did(did_for(chain, "fulcio:issuer:"), chain)
        with pytest.raises(ValueError, match="Fulcio predicate does not match"):
            resolve_did(did_for(chain, "fulcio:issuer:nonempty"), chain)


@pytest.mark.parametrize("oid", [FULCIO_ISSUER_OID, *FIELD_OIDS.values()])
def test_every_critical_custom_extension_fails_mapping_and_path_validation(oid):
    payload = (
        LEGACY_ISSUER.encode() if oid == FULCIO_ISSUER_OID
        else der_value(0x0C, b"opaque")
    )
    chain = make_chain(extra_extensions=[raw_extension(oid, payload, True)])
    with pytest.raises(ValueError, match="Certificate contains a critical Fulcio extension"):
        decode_certificate(chain[0])
    with pytest.raises(ValueError, match="Certificate contains a critical Fulcio extension"):
        check_did_x509(did_for(chain, "subject:CN:Leaf"), chain)
    with pytest.raises(ValueError, match="Certificate chain verification failed: unhandled critical extension"):
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)


@pytest.mark.parametrize("oid", [FULCIO_ISSUER_OID, FIELD_OIDS["issuer"], FIELD_OIDS["token-subject"]])
def test_critical_fulcio_on_the_trust_anchor_is_not_ignored(oid):
    payload = LEGACY_ISSUER.encode() if oid == FULCIO_ISSUER_OID else b"\x0c\x01a"
    chain = make_chain(root_extensions=[raw_extension(oid, payload, True)])
    with pytest.raises(ValueError, match="critical"):
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)


@pytest.mark.parametrize("suffix", range(2, 8))
def test_unregistered_standalone_extensions_do_not_synthesize_fields(suffix):
    chain = make_chain(extra_extensions=[
        raw_extension(f"1.3.6.1.4.1.57264.1.{suffix}", b"not-der")
    ])
    assert "fulcio" not in decode_certificate(chain[0])["extensions"]
    with pytest.raises(ValueError, match="does not contain the requested Fulcio extension"):
        resolve_did(did_for(chain, "fulcio:issuer:opaque"), chain)


@pytest.mark.parametrize("predicate,message", [
    ("fulcio", "DID contains an invalid predicate value."),
    ("fulcio:", "DID contains an invalid predicate value."),
    ("fulcio:issuer", "Fulcio predicate requires exactly one field and value."),
    ("fulcio:issuer:", "DID contains an invalid predicate value."),
    ("fulcio::opaque", "DID contains an invalid predicate value."),
    ("fulcio:issuer:opaque:extra", "Fulcio predicate requires exactly one field and value."),
    ("fulcio:token-subject:repo:pypa", "Fulcio predicate requires exactly one field and value."),
    ("fulcio:username:opaque", "Fulcio predicate contains an unknown field."),
    ("fulcio:Issuer:opaque", "Fulcio predicate contains an unknown field."),
    ("fulcio:%69ssuer:opaque", "Fulcio predicate contains an unknown field."),
    ("fulcio:1.3.6.1.4.1.57264.1.8:opaque", "Fulcio predicate contains an unknown field."),
    ("fulcio:8:opaque", "Fulcio predicate contains an unknown field."),
    ("fulcio:source_repository_uri:opaque", "Fulcio predicate contains an unknown field."),
    ("Fulcio:issuer:opaque", "DID contains an unknown predicate."),
    ("fulcio:issuer:opaque%", "DID contains an invalid predicate value."),
    ("fulcio:issuer:opaque%2", "DID contains an invalid predicate value."),
    ("fulcio:issuer:opaque%GG", "DID contains an invalid predicate value."),
    ("fulcio:issuer:opaque+", "DID contains an invalid predicate value."),
    ("fulcio:issuer:opaque~", "DID contains an invalid predicate value."),
    ("fulcio:issuer:caf\u00e9", "DID contains an invalid predicate value."),
])
def test_selector_arity_literal_fields_and_percent_syntax(predicate, message):
    chain = make_chain(extra_extensions=[fulcio_extension("issuer", "opaque")])
    with pytest.raises(ValueError) as error:
        resolve_did(did_for(chain, predicate), chain)
    assert str(error.value) == message


@pytest.mark.parametrize("field,value,encoded", [
    ("issuer", "urn:example:issuer", "urn%3Aexample%3Aissuer"),
    ("issuer", "http://EXAMPLE.com:80/a%2F", "http%3A%2F%2FEXAMPLE.com%3A80%2Fa%252F"),
    ("build-signer-digest", "sha1:AbCd0123", "sha1%3AAbCd0123"),
    ("source-repository-identifier", "00042", "00042"),
    ("runner-environment", "custom/provider", "custom%2Fprovider"),
    ("source-repository-visibility-at-signing", "custom", "custom"),
    ("source-repository-uri", "https://x/a%2F?q=%25#frag", "https%3A%2F%2Fx%2Fa%252F%3Fq%3D%2525%23frag"),
    ("token-subject", "repo:a/b:environment:pypi", "repo%3Aa%2Fb%3Aenvironment%3Apypi"),
    ("token-subject", "a:b::c%+~!d", "a%3Ab%3A%3Ac%25%2B%7E%21d"),
    ("token-subject", "a:b::c%+~!d", "a%3ab%3a%3ac%25%2b%7e%21d"),
    ("deployment-environment", "\u00e9\u4f8b", "%C3%A9%E4%BE%8B"),
    ("deployment-environment", "\u00e9\u4f8b", "%c3%a9%e4%be%8b"),
    ("token-subject", "literal%3A%3A", "literal%253A%253A"),
    ("token-subject", "\ufffd", "%EF%BF%BD"),
    ("token-subject", "\x00", "%00"),
])
def test_scalars_decode_once_without_field_specific_interpretation(field, value, encoded):
    chain = make_chain(extra_extensions=[fulcio_extension(field, value)])
    assert pctencode(value).lower() == encoded.lower()
    did = did_for(chain, f"fulcio:{field}:{encoded}")
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("field,value,other", [
    ("issuer", "https://EXAMPLE.com/a", "https://example.com/a"),
    ("issuer", "https://example.com:443/a", "https://example.com/a"),
    ("issuer", "https://example.com/a", "https://example.com/a/"),
    ("issuer", "http://example.com", "https://example.com"),
    ("source-repository-uri", "https://x/a%2F", "https://x/a/"),
    ("source-repository-identifier", "00042", "42"),
    ("build-signer-digest", "sha1:AbCd", "sha1:abcd"),
    ("build-signer-digest", "sha1:abc123", "abc123"),
    ("token-subject", "literal%3A", "literal:"),
    ("token-subject", "a:b", "a%3Ab"),
    ("token-subject", "\u00e9", "e\u0301"),
    ("token-subject", "e\u0301", "\u00e9"),
    ("deployment-environment", " pypi", "pypi"),
    ("deployment-environment", "pypi", "*"),
])
def test_scalar_comparison_is_exact(field, value, other):
    chain = make_chain(extra_extensions=[fulcio_extension(field, value)])
    with pytest.raises(ValueError, match="Fulcio predicate does not match"):
        resolve_did(did_for(chain, selector(field, other)), chain)


@pytest.mark.parametrize("encoded", INVALID_PERCENT_UTF8)
@pytest.mark.parametrize("field", ["issuer", "source-repository-uri", "token-subject"])
def test_invalid_percent_utf8_never_matches_a_replacement_character(encoded, field):
    chain = make_chain(extra_extensions=[fulcio_extension(field, "\ufffd")])
    with pytest.raises(ValueError, match="Percent-encoded value is not valid UTF-8"):
        resolve_did(did_for(chain, f"fulcio:{field}:{encoded}"), chain)


def test_document_ids_preserve_selected_dids_and_only_remove_fragments():
    chain = make_chain(extra_extensions=[fulcio_extension("issuer", "https://x/a")])
    upper = did_for(chain, "fulcio:issuer:https%3A%2F%2Fx%2Fa")
    lower = did_for(chain, "fulcio:issuer:https%3a%2f%2fx%2fa")
    for did in [upper, lower]:
        document = resolve_did(f"{did}#requested", chain)
        assert document["id"] == did
        assert document["verificationMethod"][0]["id"] == f"{did}#0"
        assert document["verificationMethod"][0]["controller"] == did
    assert resolve_did(upper, chain)["id"] != resolve_did(lower, chain)["id"]


@pytest.mark.parametrize("ca,invalid_signature", [(False, False), (True, True)])
def test_fulcio_does_not_bypass_ca_or_signature_validation(ca, invalid_signature):
    chain = make_chain(
        extra_extensions=[fulcio_extension("issuer", V2_ISSUER)],
        ca=ca, invalid_signature=invalid_signature,
    )
    with pytest.raises(ValueError, match="Certificate chain verification failed"):
        resolve_did(did_for(chain, selector("issuer", V2_ISSUER)), chain)


def test_fulcio_does_not_bypass_name_constraints():
    chain = make_chain(
        [x509.DNSName("outside.invalid")],
        extra_extensions=[fulcio_extension("issuer", V2_ISSUER)],
        root_extensions=[(x509.NameConstraints([x509.DNSName(".example.com")], None), True)],
    )
    with pytest.raises(ValueError, match="Certificate chain verification failed: permitted subtree violation"):
        resolve_did(did_for(chain, selector("issuer", V2_ISSUER)), chain)


def test_cli_convert_and_resolve_use_the_additive_model(full_fields_chain, capsys):
    sample = SAMPLES[FULL_SAMPLE_ID]
    path = str(FIXTURE_DIR / sample["chain"])
    cli_convert(path)
    model = json.loads(capsys.readouterr().out)
    assert model == [decode_certificate(cert) for cert in full_fields_chain]
    assert model[0]["extensions"]["fulcio"] == sample["fulcio"]
    assert model[0]["extensions"]["fulcio_issuer"] == sample["fulcio_issuer"]
    did = did_for(full_fields_chain, selector("token-subject", sample["fulcio"]["token-subject"]))
    cli_resolve(did, path)
    assert json.loads(capsys.readouterr().out)["id"] == did


@pytest.mark.parametrize("extension,message", [
    (fulcio_extension("issuer", V2_ISSUER, True), "critical Fulcio extension"),
    (legacy_extension(critical=True), "critical Fulcio extension"),
    (raw_extension(FIELD_OIDS["token-subject"], b"\x0c\x01\xff"), "not valid UTF-8"),
])
def test_cli_convert_fails_instead_of_silently_ignoring_registered_extensions(
    extension, message, tmp_path, capsys
):
    chain = make_chain(extra_extensions=[extension])
    path = tmp_path / "chain.pem"
    path.write_bytes(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain))
    with pytest.raises(ValueError, match=message):
        cli_convert(str(path))
    assert capsys.readouterr().out == ""
