# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Mapping a chain to the JSON model fails with ValueError, never with
library-specific or unrelated exception types, even when RFC 5280 path
validation accepts the chain."""

from typing import Annotated

import pytest
from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from didx509.didx509 import check_did_x509, decode_certificate, resolve_did
from test_san_othername import did_for, make_chain


# RFC 5280 section 4.1, with each CHOICE narrowed to the alternatives the test
# chains use. cryptography's builder refuses duplicate extensions, so the
# TBSCertificate is edited and re-signed through this model instead.
@asn1.sequence
class AlgorithmIdentifier:
    algorithm: x509.ObjectIdentifier
    parameters: x509.ObjectIdentifier | asn1.Null | None


@asn1.sequence
class AttributeTypeAndValue:
    type: x509.ObjectIdentifier
    value: str | asn1.PrintableString | asn1.IA5String


Name = list[asn1.SetOf[AttributeTypeAndValue]]
Time = asn1.UTCTime | asn1.GeneralizedTime


@asn1.sequence
class Validity:
    not_before: Time
    not_after: Time


@asn1.sequence
class SubjectPublicKeyInfo:
    algorithm: AlgorithmIdentifier
    subject_public_key: asn1.BitString


@asn1.sequence
class Extension:
    extn_id: x509.ObjectIdentifier
    critical: Annotated[bool, asn1.Default(False)] = False
    extn_value: bytes


@asn1.sequence
class TBSCertificate:
    version: Annotated[int, asn1.Explicit(0), asn1.Default(0)]
    serial_number: int
    signature: AlgorithmIdentifier
    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info: SubjectPublicKeyInfo
    issuer_unique_id: Annotated[asn1.BitString | None, asn1.Implicit(1)]
    subject_unique_id: Annotated[asn1.BitString | None, asn1.Implicit(2)]
    extensions: Annotated[list[Extension] | None, asn1.Explicit(3)]


@asn1.sequence
class Certificate:
    tbs_certificate: TBSCertificate
    signature_algorithm: AlgorithmIdentifier
    signature_value: asn1.BitString


# The two GeneralName alternatives cryptography does not support.
@asn1.sequence
class BuiltInStandardAttributes:
    """Every component is OPTIONAL, so the empty SEQUENCE is a valid value."""


@asn1.sequence
class ORAddress:
    built_in_standard_attributes: BuiltInStandardAttributes


@asn1.sequence
class EDIPartyName:
    party_name: Annotated[str, asn1.Explicit(1)]


@asn1.sequence
class SubjectAltNameWithUnsupportedName:
    """GeneralNames holding a dNSName and an unsupported name. A two-field
    SEQUENCE encodes identically to the SEQUENCE OF, which the declarative API
    cannot emit bare."""

    dns_name: Annotated[asn1.IA5String, asn1.Implicit(2)]
    unsupported: (
        Annotated[ORAddress, asn1.Implicit(3)]
        | Annotated[EDIPartyName, asn1.Implicit(5)]
    )


def append_extension(certificate, signing_key, extension: Extension):
    """Re-sign a certificate with one more extension appended."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    decoded = asn1.decode_der(Certificate, der)
    decoded.tbs_certificate.extensions.append(extension)
    tbs = asn1.encode_der(decoded.tbs_certificate)
    decoded.signature_value = asn1.BitString(data=signing_key.sign(tbs), padding_bits=0)
    return x509.load_der_x509_certificate(asn1.encode_der(decoded))


@pytest.fixture
def root_key():
    return ed25519.Ed25519PrivateKey.generate()


def test_appending_a_distinct_extension_keeps_the_chain_resolvable(root_key):
    issuer = x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), asn1.encode_der("https://a")
    )
    leaf, root = make_chain(extra_extensions=[(issuer, False)], root_key=root_key)
    token_subject = Extension(
        extn_id=x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.24"),
        extn_value=asn1.encode_der("alice"),
    )
    leaf = append_extension(leaf, root_key, token_subject)
    chain = [leaf, root]
    did = did_for(chain, "fulcio:issuer:https%3A%2F%2Fa::fulcio:token-subject:alice")
    assert resolve_did(did, chain)["id"] == did


@pytest.mark.parametrize("suffix,value", [(1, "https://a"), (8, "https://a"), (24, "alice")])
def test_duplicate_extensions_fail_mapping_with_value_error(root_key, suffix, value):
    oid = f"1.3.6.1.4.1.57264.1.{suffix}"
    payload = value.encode() if suffix == 1 else asn1.encode_der(value)
    original = x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), payload)
    leaf, root = make_chain(extra_extensions=[(original, False)], root_key=root_key)
    duplicate = Extension(extn_id=x509.ObjectIdentifier(oid), extn_value=payload)
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
    pytest.param(
        ORAddress(built_in_standard_attributes=BuiltInStandardAttributes()), id="x400Address"
    ),
    pytest.param(EDIPartyName(party_name="party"), id="ediPartyName"),
])
@pytest.mark.parametrize("critical", [False, True])
def test_unsupported_general_name_types_fail_mapping_with_value_error(general_name, critical):
    names = SubjectAltNameWithUnsupportedName(
        dns_name=asn1.IA5String("example.com"), unsupported=general_name
    )
    san = x509.UnrecognizedExtension(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME, asn1.encode_der(names)
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
