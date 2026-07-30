# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""RFC 5280 certification path validation tests.

These cover specification step 2, which the DID-string tests in test.py do not
exercise. Chains are generated synthetically so that individual path validation
inputs can be varied independently.
"""

import base64
import datetime
import json
import re
from typing import List

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from didx509.didx509 import b64url, resolve_did

NOT_BEFORE = datetime.datetime(2020, 1, 1)
NOT_AFTER = datetime.datetime(2120, 1, 1)

ROOT = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
INTERMEDIATE = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Inter")])
INTERMEDIATE_2 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Inter2")])
LEAF = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])

CA_UNLIMITED = (x509.BasicConstraints(True, None), True)
NOT_CA = (x509.BasicConstraints(False, None), True)
KEY_CERT_SIGN = (
    x509.KeyUsage(False, False, False, False, False, True, False, False, False),
    True,
)
DIGITAL_SIGNATURE_ONLY = (
    x509.KeyUsage(True, False, False, False, False, False, False, False, False),
    True,
)


def ca(path_length=None):
    return (x509.BasicConstraints(True, path_length), True)


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign_certificate(subject, subject_key, issuer, issuer_key, extensions, **kwargs):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(kwargs.pop("not_before", NOT_BEFORE))
        .not_valid_after(kwargs.pop("not_after", NOT_AFTER))
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical)
    return builder.sign(issuer_key, kwargs.pop("algorithm", hashes.SHA256()), **kwargs)


def build_chain(intermediate_extensions, root_extensions, leaf_extensions=(NOT_CA,)):
    """Build a leaf-first three-certificate chain."""
    root_key, intermediate_key, leaf_key = new_key(), new_key(), new_key()
    return [
        sign_certificate(
            LEAF, leaf_key, INTERMEDIATE, intermediate_key, list(leaf_extensions)
        ),
        sign_certificate(
            INTERMEDIATE,
            intermediate_key,
            ROOT,
            root_key,
            list(intermediate_extensions),
        ),
        sign_certificate(ROOT, root_key, ROOT, root_key, list(root_extensions)),
    ]


def subject_did(chain: List[x509.Certificate]) -> str:
    fingerprint = b64url(chain[-1].fingerprint(hashes.SHA256()))
    return f"did:x509:0:sha256:{fingerprint}::subject:CN:Leaf"


def resolve(chain: List[x509.Certificate], did=None, **kwargs):
    return resolve_did(did or subject_did(chain), chain, **kwargs)


# Validity periods (RFC 5280 6.1.3(a)(2)). Checked by default; the
# skip_validity_period_check option suppresses the check at every depth, which
# the fixtures in test-data/ need because they are real, expired certificates.

EXPIRED = dict(
    not_before=datetime.datetime(2020, 1, 1),
    not_after=datetime.datetime(2021, 1, 1),
)
NOT_YET_VALID = dict(
    not_before=datetime.datetime(2119, 1, 1),
    not_after=datetime.datetime(2120, 1, 1),
)


def build_chain_with_validity(depth, validity):
    """Build a three-certificate chain, with `validity` applied at `depth`."""
    root_key, intermediate_key, leaf_key = new_key(), new_key(), new_key()
    at = lambda i: validity if i == depth else {}
    return [
        sign_certificate(
            LEAF, leaf_key, INTERMEDIATE, intermediate_key, [NOT_CA], **at(0)
        ),
        sign_certificate(
            INTERMEDIATE,
            intermediate_key,
            ROOT,
            root_key,
            [CA_UNLIMITED, KEY_CERT_SIGN],
            **at(1),
        ),
        sign_certificate(
            ROOT, root_key, ROOT, root_key, [CA_UNLIMITED, KEY_CERT_SIGN], **at(2)
        ),
    ]


@pytest.mark.parametrize("depth", [0, 1, 2])
def test_expired_certificate_is_rejected(depth):
    with pytest.raises(ValueError, match="expired"):
        resolve(build_chain_with_validity(depth, EXPIRED))


@pytest.mark.parametrize("depth", [0, 1, 2])
def test_expired_certificate_is_accepted_when_check_skipped(depth):
    resolve(build_chain_with_validity(depth, EXPIRED), skip_validity_period_check=True)


def test_not_yet_valid_certificate_is_rejected():
    with pytest.raises(ValueError, match="not yet valid"):
        resolve(build_chain_with_validity(0, NOT_YET_VALID))


def test_skipping_the_validity_check_does_not_relax_other_checks():
    chain = build_chain([NOT_CA, KEY_CERT_SIGN], [CA_UNLIMITED, KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="CA"):
        resolve(chain, skip_validity_period_check=True)


def test_skipping_the_validity_check_does_not_relax_other_checks():
    chain = build_chain([NOT_CA, KEY_CERT_SIGN], [CA_UNLIMITED, KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="CA"):
        resolve(chain, skip_validity_period_check=True)


# Path length constraints (RFC 5280 4.2.1.9). pathLenConstraint is a ceiling on
# the number of intermediates that may follow a CA, so a violation means the
# constraint is too small for the chain presented, never too large.


def test_path_length_permits_exact_depth():
    resolve(build_chain([ca(0), KEY_CERT_SIGN], [ca(1), KEY_CERT_SIGN]))


def test_path_length_permits_excess_headroom():
    resolve(build_chain([ca(3), KEY_CERT_SIGN], [ca(5), KEY_CERT_SIGN]))


def test_path_length_zero_rejects_intermediate():
    chain = build_chain([ca(0), KEY_CERT_SIGN], [ca(0), KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="path length"):
        resolve(chain)


def test_path_length_zero_rejects_two_intermediates():
    root_key, first_key, second_key, leaf_key = (new_key() for _ in range(4))
    chain = [
        sign_certificate(LEAF, leaf_key, INTERMEDIATE_2, second_key, [NOT_CA]),
        sign_certificate(
            INTERMEDIATE_2,
            second_key,
            INTERMEDIATE,
            first_key,
            [CA_UNLIMITED, KEY_CERT_SIGN],
        ),
        sign_certificate(
            INTERMEDIATE, first_key, ROOT, root_key, [CA_UNLIMITED, KEY_CERT_SIGN]
        ),
        sign_certificate(ROOT, root_key, ROOT, root_key, [ca(0), KEY_CERT_SIGN]),
    ]
    with pytest.raises(ValueError, match="path length"):
        resolve(chain)


# Basic constraints (RFC 5280 6.1.4).


def test_issuer_without_basic_constraints_is_rejected():
    chain = build_chain([KEY_CERT_SIGN], [KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="CA"):
        resolve(chain)


def test_issuer_with_ca_false_is_rejected():
    chain = build_chain([NOT_CA, KEY_CERT_SIGN], [CA_UNLIMITED, KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="CA"):
        resolve(chain)


# Key usage (RFC 5280 6.1.4(n)).


def test_issuer_without_key_cert_sign_is_rejected():
    chain = build_chain(
        [CA_UNLIMITED, DIGITAL_SIGNATURE_ONLY], [CA_UNLIMITED, KEY_CERT_SIGN]
    )
    with pytest.raises(ValueError, match="CA"):
        resolve(chain)


def test_issuer_with_key_cert_sign_is_accepted():
    resolve(build_chain([CA_UNLIMITED, KEY_CERT_SIGN], [CA_UNLIMITED, KEY_CERT_SIGN]))


# Name constraints (RFC 5280 4.2.1.10). Without these, a constrained
# intermediate could vouch for any name that a did:x509 predicate matches on.

LEAF_SAN = (x509.SubjectAlternativeName([x509.DNSName("host.example.com")]), False)


def san_did(chain: List[x509.Certificate]) -> str:
    fingerprint = b64url(chain[-1].fingerprint(hashes.SHA256()))
    return f"did:x509:0:sha256:{fingerprint}::san:dns:host.example.com"


def build_name_constrained_chain(name_constraints):
    return build_chain(
        [CA_UNLIMITED, KEY_CERT_SIGN, (name_constraints, True)],
        [CA_UNLIMITED, KEY_CERT_SIGN],
        leaf_extensions=(NOT_CA, LEAF_SAN),
    )


def test_san_within_permitted_subtree():
    chain = build_name_constrained_chain(
        x509.NameConstraints([x509.DNSName("example.com")], None)
    )
    resolve(chain, san_did(chain))


def test_san_outside_permitted_subtree_is_rejected():
    chain = build_name_constrained_chain(
        x509.NameConstraints([x509.DNSName("other.test")], None)
    )
    with pytest.raises(ValueError, match="permitted subtree"):
        resolve(chain, san_did(chain))


def test_san_within_excluded_subtree_is_rejected():
    chain = build_name_constrained_chain(
        x509.NameConstraints(None, [x509.DNSName("example.com")])
    )
    with pytest.raises(ValueError, match="excluded subtree"):
        resolve(chain, san_did(chain))


def test_broken_signature_is_rejected():
    root_key = new_key()
    chain = [
        sign_certificate(LEAF, new_key(), INTERMEDIATE, new_key(), [NOT_CA]),
        sign_certificate(
            INTERMEDIATE, new_key(), ROOT, root_key, [CA_UNLIMITED, KEY_CERT_SIGN]
        ),
        sign_certificate(
            ROOT, root_key, ROOT, root_key, [CA_UNLIMITED, KEY_CERT_SIGN]
        ),
    ]
    with pytest.raises(ValueError, match="signature"):
        resolve(chain)


def test_chain_shorter_than_two_certificates():
    chain = build_chain([CA_UNLIMITED, KEY_CERT_SIGN], [CA_UNLIMITED, KEY_CERT_SIGN])
    with pytest.raises(ValueError, match="at least two"):
        resolve_did(subject_did(chain), chain[:1])


# Critical extension processing (specification step 2). The fulcio_issuer
# extension is unrecognized for path validation purposes and must not be marked
# critical; the standard extensions in the specification's allowlist may be.

FULCIO_ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
FULCIO_ISSUER = "https://accounts.google.com"
UNKNOWN_OID = x509.ObjectIdentifier("1.2.3.4.5.6.7")


def fulcio_issuer_extension(critical):
    return (
        x509.UnrecognizedExtension(FULCIO_ISSUER_OID, FULCIO_ISSUER.encode()),
        critical,
    )


def leaf_chain(*extra_leaf_extensions):
    return build_chain(
        [CA_UNLIMITED, KEY_CERT_SIGN],
        [CA_UNLIMITED, KEY_CERT_SIGN],
        [NOT_CA, *extra_leaf_extensions],
    )


def fulcio_did(chain):
    fingerprint = b64url(chain[-1].fingerprint(hashes.SHA256()))
    return f"did:x509:0:sha256:{fingerprint}::fulcio-issuer:accounts.google.com"


def test_fulcio_issuer_extension_is_accepted_when_not_critical():
    chain = leaf_chain(fulcio_issuer_extension(False))
    resolve_did(fulcio_did(chain), chain)


def test_critical_fulcio_issuer_extension_is_rejected():
    chain = leaf_chain(fulcio_issuer_extension(True))
    with pytest.raises(ValueError, match="critical extension"):
        resolve_did(fulcio_did(chain), chain)


def test_fulcio_issuer_predicate_requires_the_extension():
    chain = leaf_chain()
    with pytest.raises(ValueError, match="Fulcio issuer extension"):
        resolve_did(fulcio_did(chain), chain)


def test_unknown_critical_extension_is_rejected():
    chain = leaf_chain((x509.UnrecognizedExtension(UNKNOWN_OID, b"x"), True))
    with pytest.raises(ValueError, match="critical extension"):
        resolve(chain)


def test_unknown_non_critical_extension_is_ignored():
    resolve(leaf_chain((x509.UnrecognizedExtension(UNKNOWN_OID, b"x"), False)))


def test_allowlisted_critical_extension_is_accepted():
    policies = x509.CertificatePolicies(
        [x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]
    )
    resolve(leaf_chain((policies, True)))


# Specification test vectors. Unlike the fixtures in test-data/, which are real
# expired certificates, the specification chain is valid at the current time, so
# these resolve with validity-period checking enabled.


def spec_test_vectors():
    specification = open("specification.md").read()
    block = re.search(r'```json\n(\[\n  "MII.*?)\n```', specification, re.S).group(1)

    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    chain = [x509.load_der_x509_certificate(decode(c)) for c in json.loads(block)]
    dids = re.findall(
        r"`(did:x509:0:[^`]+)`",
        specification.split("The following DIDs resolve")[1],
    )
    return chain, dids


def test_specification_test_vectors():
    chain, dids = spec_test_vectors()
    assert len(dids) == 4
    for did in dids:
        resolve_did(did, chain)


def test_specification_test_vectors_reject_wrong_fingerprint():
    chain, _ = spec_test_vectors()
    leaf_fingerprint = b64url(chain[0].fingerprint(hashes.SHA256()))
    with pytest.raises(ValueError, match="CA fingerprint"):
        resolve_did(
            f"did:x509:0:sha256:{leaf_fingerprint}::subject:CN:Microsoft%20Corporation",
            chain,
        )
