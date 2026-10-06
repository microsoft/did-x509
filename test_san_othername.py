# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import ipaddress
import json
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from didx509.der import decode_der_utf8_string
from didx509.didx509 import (
    SAN_OTHERNAME_DECODERS,
    b64url,
    check_did_x509,
    cli_convert,
    decode_certificate,
    parse_extensions,
    pctencode,
    resolve_did,
)
from test_vectors import TEST_VECTORS, load_vector_chain


OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7"
IDENTITY = "alice!example.com"


def der_value(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 128:
        encoded_length = bytes([length])
    else:
        octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + encoded_length + content


def othername(value: str, oid: str = OTHERNAME_OID) -> x509.OtherName:
    return x509.OtherName(
        x509.ObjectIdentifier(oid), der_value(0x0C, value.encode("utf-8"))
    )


def san_extensions(names, critical=False):
    return x509.Extensions([
        x509.Extension(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical,
            x509.SubjectAlternativeName(names),
        )
    ])


def make_chain(
    names=None,
    *,
    critical=False,
    empty_subject=False,
    extra_extensions=(),
    root_extensions=(),
    ca=True,
    invalid_signature=False,
    root_key=None,
):
    if root_key is None:
        root_key = ed25519.Ed25519PrivateKey.generate()
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "OtherName Test Root")
    ])
    leaf_name = x509.Name([]) if empty_subject else x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Leaf")
    ])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca, None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, ca, ca, None, None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    for extension, extension_critical in root_extensions:
        root = root.add_extension(extension, critical=extension_critical)
    root = root.sign(root_key, None)

    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(False, None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, None, None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    if names is not None:
        leaf = leaf.add_extension(x509.SubjectAlternativeName(names), critical)
    for extension, extension_critical in extra_extensions:
        leaf = leaf.add_extension(extension, critical=extension_critical)
    signing_key = (
        ed25519.Ed25519PrivateKey.generate() if invalid_signature else root_key
    )
    return [leaf.sign(signing_key, None), root]


def did_for(chain, predicate):
    fingerprint = b64url(chain[-1].fingerprint(hashes.SHA256()))
    return f"did:x509:0:sha256:{fingerprint}::{predicate}"


INVALID_DER = [
    (b"", "Value is not a primitive DER UTF8String.", "empty"),
    (b"alice!example.com", "Value is not a primitive DER UTF8String.", "raw-utf8"),
    (b"\x16\x01a", "Value is not a primitive DER UTF8String.", "ia5-string"),
    (b"\x13\x01a", "Value is not a primitive DER UTF8String.", "printable-string"),
    (b"\x1e\x02\x00a", "Value is not a primitive DER UTF8String.", "bmp-string"),
    (b"\x04\x01a", "Value is not a primitive DER UTF8String.", "octet-string"),
    (b"\x02\x01\x01", "Value is not a primitive DER UTF8String.", "integer"),
    (b"\x4c\x01a", "Value is not a primitive DER UTF8String.", "application-class"),
    (b"\x8c\x01a", "Value is not a primitive DER UTF8String.", "context-class"),
    (b"\xcc\x01a", "Value is not a primitive DER UTF8String.", "private-class"),
    (b"\x2c\x03\x0c\x01a", "Value is not a primitive DER UTF8String.", "constructed"),
    (b"\x1f\x0c\x01a", "Value is not a primitive DER UTF8String.", "long-form-tag"),
    (b"\x0c", "DER UTF8String length is truncated.", "missing-length"),
    (b"\x0c\x80\x00\x00", "DER UTF8String length is not definite.", "indefinite"),
    (b"\x0c\xff", "DER UTF8String length is invalid.", "reserved-length"),
    (b"\x0c\x82\x01", "DER UTF8String length is truncated.", "truncated-length"),
    (b"\x0c\x81\x01a", "DER UTF8String length is not minimal.", "long-short-length"),
    (
        b"\x0c\x82\x00\x80" + b"a" * 128,
        "DER UTF8String length is not minimal.",
        "leading-zero-length",
    ),
    (b"\x0c\x02a", "DER UTF8String must contain exactly one complete value.", "truncated"),
    (b"\x0c\x01ab", "DER UTF8String must contain exactly one complete value.", "trailing"),
    (
        b"\x0c\x01a\x0c\x01b",
        "DER UTF8String must contain exactly one complete value.",
        "two-values",
    ),
    (b"\x0c\x01\xff", "DER UTF8String is not valid UTF-8.", "invalid-utf8"),
    (b"\x0c\x02\xc0\xaf", "DER UTF8String is not valid UTF-8.", "overlong-utf8"),
    (b"\x0c\x03\xed\xa0\x80", "DER UTF8String is not valid UTF-8.", "surrogate"),
    (b"\x0c\x04\xf4\x90\x80\x80", "DER UTF8String is not valid UTF-8.", "above-unicode"),
    (b"\x0c\x01\xc3", "DER UTF8String is not valid UTF-8.", "truncated-utf8"),
]
INVALID_DER_PARAMS = [
    pytest.param(encoded, message, id=case)
    for encoded, message, case in INVALID_DER
]


@pytest.mark.parametrize(
    "value",
    ["", IDENTITY, "\ufffd", "caf\u00e9", "\U0010ffff", "\x00",
     "a" * 127, "a" * 128, "a" * 255, "a" * 256, "a" * 65536, "\u00e9" * 64],
    ids=["empty", "username", "replacement", "multibyte", "max-unicode", "nul",
         "length-127", "length-128", "length-255", "length-256", "length-65536",
         "byte-length-128"],
)
def test_der_utf8_string(value):
    assert decode_der_utf8_string(der_value(0x0C, value.encode("utf-8"))) == value


@pytest.mark.parametrize("encoded,message", INVALID_DER_PARAMS)
def test_der_utf8_string_rejects_invalid_encoding(encoded, message):
    with pytest.raises(ValueError) as error:
        decode_der_utf8_string(encoded)
    assert str(error.value) == message


def test_othername_registry_is_closed():
    assert SAN_OTHERNAME_DECODERS == {OTHERNAME_OID: decode_der_utf8_string}


@pytest.mark.parametrize("critical", [False, True])
def test_san_mapping_preserves_pairs_triples_and_duplicates(critical):
    names = [
        x509.RFC822Name("alice@example.com"),
        x509.DNSName("example.com"),
        x509.UniformResourceIdentifier("https://example.com/alice"),
        x509.DirectoryName(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Directory identity")
        ])),
        othername(IDENTITY),
        othername("bob!example.com"),
        othername(IDENTITY),
    ]
    assert parse_extensions(san_extensions(names, critical)) == {
        "san": [
            ["email", "alice@example.com"],
            ["dns", "example.com"],
            ["uri", "https://example.com/alice"],
            ["dn", {"CN": "Directory identity"}],
            ["othername", OTHERNAME_OID, IDENTITY],
            ["othername", OTHERNAME_OID, "bob!example.com"],
            ["othername", OTHERNAME_OID, IDENTITY],
        ]
    }


@pytest.mark.parametrize("encoded,message", INVALID_DER_PARAMS)
@pytest.mark.parametrize("bad_first", [False, True])
def test_one_malformed_othername_fails_the_whole_mapping(encoded, message, bad_first):
    bad = x509.OtherName(x509.ObjectIdentifier(OTHERNAME_OID), encoded)
    names = [bad, othername(IDENTITY)] if bad_first else [othername(IDENTITY), bad]
    with pytest.raises(ValueError) as error:
        parse_extensions(san_extensions(names))
    assert str(error.value) == message


@pytest.mark.parametrize("oid", [
    "1.3.6.1.4.1.57264.1.1", "1.3.6.1.4.1.57264.1.8",
    "1.3.6.1.4.1.57264.1.24", "1.2.3.4",
])
@pytest.mark.parametrize("critical", [False, True])
def test_unregistered_othername_fails_even_alongside_a_match(oid, critical):
    chain = make_chain(
        [othername(IDENTITY), othername(IDENTITY, oid), x509.DNSName("example.com")],
        critical=critical,
    )
    for predicate in [
        f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}",
        "san:dns:example.com",
        "subject:CN:Leaf",
    ]:
        with pytest.raises(ValueError, match="Certificate contains an unsupported SAN type"):
            resolve_did(did_for(chain, predicate), chain)


def test_othername_does_not_enable_unsupported_ip_sans():
    chain = make_chain([
        othername(IDENTITY), x509.IPAddress(ipaddress.ip_address("192.0.2.1"))
    ])
    with pytest.raises(ValueError, match="Certificate contains an unsupported SAN type"):
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)


@pytest.mark.parametrize("critical,empty_subject", [
    (False, False), (True, False), (True, True),
])
def test_registered_othername_resolves(critical, empty_subject):
    chain = make_chain([othername(IDENTITY)], critical=critical, empty_subject=empty_subject)
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    document = resolve_did(did, chain)
    assert document["id"] == did
    assert document["verificationMethod"][0]["publicKeyJwk"]["kty"] == "OKP"
    assert "keyAgreement" not in document


@pytest.mark.parametrize("suffixes", [(), ("1",), ("8",), ("24",), ("1", "8", "24")])
def test_othername_is_independent_of_standalone_fulcio_extensions(suffixes):
    values = {
        "1": b"https://issuer.example.com",
        "8": der_value(0x0C, b"https://issuer.example.com"),
        "24": der_value(0x0C, b"alice"),
    }
    extensions = [
        (x509.UnrecognizedExtension(
            x509.ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{suffix}"), values[suffix]
        ), False)
        for suffix in suffixes
    ]
    chain = make_chain([othername(IDENTITY)], critical=True, extra_extensions=extensions)
    predicate = f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}"
    if "1" in suffixes:
        predicate += "::fulcio-issuer:issuer.example.com"
    did = did_for(chain, predicate)
    assert resolve_did(did, chain)["id"] == did
    with pytest.raises(ValueError, match="SAN predicate does not match"):
        check_did_x509(did_for(chain, f"san:othername:{OTHERNAME_OID}:alice"), chain)


@pytest.mark.parametrize("suffix", ["7", "24"])
@pytest.mark.parametrize("has_legacy_san", [False, True])
def test_standalone_extensions_cannot_supply_a_san_match(suffix, has_legacy_san):
    extension = x509.UnrecognizedExtension(
        x509.ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{suffix}"),
        der_value(0x0C, IDENTITY.encode()),
    )
    chain = make_chain(
        [x509.DNSName("example.com")] if has_legacy_san else None,
        extra_extensions=[(extension, False)],
    )
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    message = (
        "SAN predicate does not match" if has_legacy_san
        else "Certificate does not contain a SAN extension"
    )
    with pytest.raises(ValueError, match=message):
        resolve_did(did, chain)


@pytest.mark.parametrize("value,encoded", [
    (IDENTITY, "alice%21example.com"),
    ("a:b::c%+~!d", "a%3Ab%3A%3Ac%25%2B%7E%21d"),
    ("a:b::c%+~!d", "a%3ab%3a%3ac%25%2b%7e%21d"),
    ("\u00e9!\u4f8b.example", "%C3%A9%21%E4%BE%8B.example"),
    ("\u00e9!\u4f8b.example", "%c3%a9%21%e4%be%8b.example"),
    ("alice%21example.com", "alice%2521example.com"),
    ("alice%3A%3Aexample.com", "alice%253A%253Aexample.com"),
    ("\ufffd", "%EF%BF%BD"),
    ("a" * 128, "a" * 128),
])
def test_othername_decodes_scalar_exactly_once(value, encoded):
    chain = make_chain([othername(value)])
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{encoded}")
    assert check_did_x509(did, chain) == did


@pytest.mark.parametrize("value,encoded", [
    (IDENTITY, "alice%2521example.com"),
    (IDENTITY, "ALICE%21example.com"),
    (IDENTITY, "alice%21EXAMPLE.com"),
    (IDENTITY, "%20alice%21example.com"),
    (" alice!example.com", "alice%21example.com"),
    (IDENTITY, "%2A%21example.com"),
    ("\u00e9", "e%CC%81"),
    ("e\u0301", "%C3%A9"),
    ("https://EXAMPLE.com/a", "https%3A%2F%2Fexample.com%2Fa"),
    ("https://example.com/a", "https%3A%2F%2Fexample.com%2Fa%2F"),
])
def test_othername_comparison_is_exact(value, encoded):
    chain = make_chain([othername(value)])
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{encoded}")
    with pytest.raises(ValueError, match="SAN predicate does not match"):
        check_did_x509(did, chain)


@pytest.mark.parametrize("encoded", [
    "%FF", "%FE", "%80", "%C3", "%C0%AF", "%ED%A0%80", "%F4%90%80%80", "%F0%9F",
])
def test_invalid_percent_utf8_cannot_match_a_replacement_character(encoded):
    chain = make_chain([othername("\ufffd")])
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{encoded}")
    with pytest.raises(ValueError, match="Percent-encoded value is not valid UTF-8"):
        check_did_x509(did, chain)


@pytest.mark.parametrize("predicate,message", [
    ("san", "DID contains an invalid predicate value."),
    ("san:", "DID contains an invalid predicate value."),
    ("san:othername", "OtherName SAN predicate requires exactly one type, OID and value."),
    (f"san:othername:{OTHERNAME_OID}", "OtherName SAN predicate requires exactly one type, OID and value."),
    (f"san:othername:{OTHERNAME_OID}:", "DID contains an invalid predicate value."),
    ("san:othername::alice", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice:extra", "OtherName SAN predicate requires exactly one type, OID and value."),
    (f"san:OtherName:{OTHERNAME_OID}:alice", "SAN predicate requires exactly one type and value."),
    ("san:othername:1.3.6.1.4.1.57264.1.8:alice", "OtherName SAN predicate contains an unsupported type OID."),
    ("san:othername:1.3.6.1.4.1.57264.1.24:alice", "OtherName SAN predicate contains an unsupported type OID."),
    ("san:othername:1.3.6.1.4.1.57264.1.%37:alice", "OtherName SAN predicate contains an unsupported type OID."),
    ("san:othername:1.3.6.1.4.1.57264.1.07:alice", "OtherName SAN predicate contains an unsupported type OID."),
    ("san:othername:1.2.3.4:alice", "OtherName SAN predicate contains an unsupported type OID."),
    (f"san:othername:{OTHERNAME_OID}:alice!", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice+", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice~", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice%", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice%2", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice%GG", "DID contains an invalid predicate value."),
    (f"san:othername:{OTHERNAME_OID}:alice::bob", "DID contains an invalid predicate value."),
    ("san:dn:Directory", "SAN predicate does not match the certificate."),
])
def test_othername_selector_syntax_and_literal_oid(predicate, message):
    chain = make_chain([othername(IDENTITY)])
    with pytest.raises(ValueError) as error:
        check_did_x509(did_for(chain, predicate), chain)
    assert str(error.value) == message


def test_repeated_predicates_match_existentially_without_consuming_entries():
    chain = make_chain([othername(IDENTITY), othername("bob!example.com"), othername(IDENTITY)])
    alice = f"san:othername:{OTHERNAME_OID}:alice%21example.com"
    bob = f"san:othername:{OTHERNAME_OID}:bob%21example.com"
    did = did_for(chain, f"{alice}::{bob}::{alice}")
    assert resolve_did(did, chain)["id"] == did
    missing = f"{did}::san:othername:{OTHERNAME_OID}:carol%21example.com"
    with pytest.raises(ValueError, match="SAN predicate does not match"):
        check_did_x509(missing, chain)


@pytest.mark.parametrize("bad_wrapper", [
    der_value(0x0C, b"alice"),
    der_value(0x80, der_value(0x0C, b"alice")),
    der_value(0xA1, der_value(0x0C, b"alice")),
    der_value(0xA0, der_value(0x0C, b"alice") + der_value(0x0C, b"bob")),
])
def test_cryptography_rejects_malformed_othername_explicit_wrappers(bad_wrapper):
    # Raw SAN bytes keep malformed wrappers out of the typed builder's validation.
    oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01\x07"
    san = der_value(0x30, der_value(0xA0, oid + bad_wrapper))
    chain = make_chain(extra_extensions=[
        (x509.UnrecognizedExtension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, san), False)
    ])
    with pytest.raises(ValueError):
        decode_certificate(chain[0])
    with pytest.raises(ValueError):
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)


def test_duplicate_san_extensions_are_invalid_not_duplicate_entries():
    vector = next(
        vector for vector in TEST_VECTORS
        if vector["id"] == "san-othername-duplicate-san-extension-is-rejected"
    )
    chain = load_vector_chain(vector)
    chain[1].public_key().verify(chain[0].signature, chain[0].tbs_certificate_bytes)
    with pytest.raises(x509.DuplicateExtension):
        decode_certificate(chain[0])
    with pytest.raises(ValueError, match="Certificate chain verification failed"):
        resolve_did(vector["input"]["did"], chain)


@pytest.mark.parametrize("suffix", ["1", "7", "8", "24"])
def test_othername_does_not_bypass_unknown_critical_extensions(suffix):
    extension = x509.UnrecognizedExtension(
        x509.ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{suffix}"),
        der_value(0x0C, b"issuer.example.com"),
    )
    chain = make_chain([othername(IDENTITY)], critical=True, extra_extensions=[(extension, True)])
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    with pytest.raises(ValueError, match="Certificate chain verification failed: unhandled critical extension"):
        resolve_did(did, chain)


@pytest.mark.parametrize("ca,invalid_signature", [(False, False), (True, True)])
def test_othername_does_not_bypass_ca_or_signature_validation(ca, invalid_signature):
    chain = make_chain([othername(IDENTITY)], ca=ca, invalid_signature=invalid_signature)
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    with pytest.raises(ValueError, match="Certificate chain verification failed"):
        resolve_did(did, chain)


@pytest.mark.parametrize("dns,accepted", [
    ("host.example.com", True), ("host.invalid.example", False),
])
def test_othername_does_not_bypass_dns_name_constraints(dns, accepted):
    constraints = x509.NameConstraints([x509.DNSName(".example.com")], None)
    chain = make_chain(
        [othername(IDENTITY), x509.DNSName(dns)],
        root_extensions=[(constraints, True)],
    )
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    if accepted:
        assert resolve_did(did, chain)["id"] == did
    else:
        with pytest.raises(ValueError, match="Certificate chain verification failed: permitted subtree violation"):
            resolve_did(did, chain)


def test_unsupported_critical_othername_constraints_still_fail():
    constraints = x509.NameConstraints([othername(IDENTITY)], None)
    chain = make_chain([othername(IDENTITY)], root_extensions=[(constraints, True)])
    did = did_for(chain, f"san:othername:{OTHERNAME_OID}:{pctencode(IDENTITY)}")
    with pytest.raises(ValueError, match="Certificate chain verification failed: unsupported name constraint type"):
        resolve_did(did, chain)


def test_cli_convert_retains_the_oid_and_scalar(tmp_path, capsys):
    chain = make_chain([x509.DNSName("example.com"), othername(IDENTITY)])
    path = tmp_path / "chain.pem"
    path.write_bytes(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain))
    cli_convert(str(path))
    model = json.loads(capsys.readouterr().out)
    assert model == [decode_certificate(cert) for cert in chain]
    assert model[0]["extensions"]["san"] == [
        ["dns", "example.com"], ["othername", OTHERNAME_OID, IDENTITY],
    ]
