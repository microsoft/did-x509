# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Mapping a chain to the JSON model fails with ValueError, never with
library-specific or unrelated exception types, even when RFC 5280 path
validation accepts the chain."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from didx509.didx509 import check_did_x509, decode_certificate, resolve_did
from test_san_othername import der_value, did_for, make_chain


ED25519_ALGORITHM = bytes.fromhex("300506032b6570")
FULCIO_ARC = bytes.fromhex("2b0601040183bf3001")


def read_tlv(data: bytes, offset: int = 0):
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        octets = length & 0x7F
        length = int.from_bytes(data[offset : offset + octets], "big")
        offset += octets
    return data[offset : offset + length], offset + length


def split_tlvs(content: bytes):
    tlvs, offset = [], 0
    while offset < len(content):
        _, end = read_tlv(content, offset)
        tlvs.append(content[offset:end])
        offset = end
    return tlvs


def fulcio_extension_der(suffix: int, value: bytes) -> bytes:
    oid = der_value(0x06, FULCIO_ARC + bytes([suffix]))
    return der_value(0x30, oid + der_value(0x04, der_value(0x0C, value)))


def append_extension(certificate, signing_key, extension_der: bytes):
    """Re-sign a certificate with one more raw extension appended.

    cryptography's builder refuses duplicate extensions, so duplicates are
    produced by editing the TBSCertificate directly.
    """
    certificate_body, _ = read_tlv(certificate.public_bytes(serialization.Encoding.DER))
    tbs_body, _ = read_tlv(split_tlvs(certificate_body)[0])
    elements = split_tlvs(tbs_body)
    assert elements[-1][0] == 0xA3, "extensions must be the last TBS element"
    extensions_body, _ = read_tlv(read_tlv(elements[-1])[0])
    extensions = der_value(0xA3, der_value(0x30, extensions_body + extension_der))
    tbs = der_value(0x30, b"".join(elements[:-1]) + extensions)
    signature = der_value(0x03, b"\x00" + signing_key.sign(tbs))
    return x509.load_der_x509_certificate(
        der_value(0x30, tbs + ED25519_ALGORITHM + signature)
    )


@pytest.fixture
def root_key():
    return ed25519.Ed25519PrivateKey.generate()


def test_appending_a_distinct_extension_keeps_the_chain_resolvable(root_key):
    issuer = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), der_value(0x0C, b"https://a")
    )
    leaf, root = make_chain(extra_extensions=[(issuer, False)], root_key=root_key)
    leaf = append_extension(leaf, root_key, fulcio_extension_der(24, b"alice"))
    chain = [leaf, root]
    did = did_for(chain, "fulcio:issuer:https%3A%2F%2Fa::fulcio:token-subject:alice")
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("suffix,value", [(1, b"https://a"), (8, b"https://a"), (24, b"alice")])
def test_duplicate_extensions_fail_mapping_with_value_error(root_key, suffix, value):
    oid = f"1.3.6.1.4.1.57264.1.{suffix}"
    payload = value if suffix == 1 else der_value(0x0C, value)
    original = x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), payload)
    leaf, root = make_chain(extra_extensions=[(original, False)], root_key=root_key)
    duplicate = der_value(
        0x30,
        der_value(0x06, FULCIO_ARC + bytes([suffix])) + der_value(0x04, payload),
    )
    leaf = append_extension(leaf, root_key, duplicate)
    chain = [leaf, root]
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)

    message = f"Certificate contains a duplicate {oid} extension."
    with pytest.raises(ValueError) as error:
        decode_certificate(leaf)
    assert str(error.value) == message
    for predicate in ["subject:CN:Leaf", "fulcio-issuer:a", "fulcio:issuer:https%3A%2F%2Fa"]:
        with pytest.raises(ValueError) as error:
            check_did_x509(did_for(chain, predicate), chain)
        assert str(error.value) == message
        # Path validation does not reject duplicates of OIDs it does not know.
        with pytest.raises(ValueError) as error:
            resolve_did(did_for(chain, predicate), chain)
        assert str(error.value) == message


@pytest.mark.parametrize("general_name", [
    pytest.param(der_value(0xA3, der_value(0x30, b"")), id="x400Address"),
    pytest.param(der_value(0xA5, der_value(0xA1, der_value(0x0C, b"party"))), id="ediPartyName"),
])
@pytest.mark.parametrize("critical", [False, True])
def test_unsupported_general_name_types_fail_mapping_with_value_error(general_name, critical):
    dns = der_value(0x82, b"example.com")
    san = x509.UnrecognizedExtension(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, der_value(0x30, dns + general_name)
    )
    chain = make_chain(extra_extensions=[(san, critical)])
    message = "Certificate contains an unsupported SAN type."
    with pytest.raises(ValueError) as error:
        decode_certificate(chain[0])
    assert str(error.value) == message
    for predicate in ["subject:CN:Leaf", "san:dns:example.com"]:
        with pytest.raises(ValueError) as error:
            resolve_did(did_for(chain, predicate), chain)
        assert str(error.value) == message


def test_critical_extensions_outside_the_permitted_list_fail_with_value_error():
    # OpenSSL processes critical CRL distribution points, but the specification
    # does not list the extension, so mapping must still fail.
    crl_distribution_points = x509.CRLDistributionPoints([
        x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://crl.example.com/leaf.crl")],
            None, None, None,
        )
    ])
    chain = make_chain(extra_extensions=[(crl_distribution_points, True)])
    message = "Certificate contains an unsupported critical extension."
    with pytest.raises(ValueError) as error:
        decode_certificate(chain[0])
    assert str(error.value) == message
    with pytest.raises(ValueError) as error:
        resolve_did(did_for(chain, "subject:CN:Leaf"), chain)
    assert str(error.value) == message

    non_critical = make_chain(extra_extensions=[(crl_distribution_points, False)])
    did = did_for(non_critical, "subject:CN:Leaf")
    assert resolve_did(did, non_critical)["id"] == did
