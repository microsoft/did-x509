# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from didx509.didx509 import (
    b64url,
    load_certificate_chain,
    pctencode,
    resolve_did,
)


FIXTURE_DIRECTORY = Path(__file__).parent / "test-data" / "fulcio-issuer-v2"
with (FIXTURE_DIRECTORY / "manifest.json").open() as manifest_file:
    MANIFEST = json.load(manifest_file)

FULCIO_OIDS = MANIFEST["fulcio_oids"]
SAMPLES = MANIFEST["samples"]
LEGACY_ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")


def der_utf8_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    length = len(encoded)
    if length < 128:
        length_bytes = bytes([length])
    else:
        octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
        length_bytes = bytes([0x80 | len(octets)]) + octets
    return b"\x0c" + length_bytes + encoded


def test_manifest():
    assert len(FULCIO_OIDS) == 17
    assert set(FULCIO_OIDS.values()) == {
        f"1.3.6.1.4.1.57264.1.{suffix}" for suffix in range(8, 25)
    }
    assert len({sample["id"] for sample in SAMPLES}) == len(SAMPLES)
    assert {sample["chain"] for sample in SAMPLES} == {
        path.name for path in FIXTURE_DIRECTORY.glob("*.pem")
    }
    assert any(set(sample["fulcio"]) == set(FULCIO_OIDS) for sample in SAMPLES)
    assert any(not sample["fulcio"] for sample in SAMPLES)


@pytest.mark.parametrize(
    "sample",
    [pytest.param(sample, id=sample["id"]) for sample in SAMPLES],
)
def test_public_certificate_sample(sample):
    chain = load_certificate_chain(FIXTURE_DIRECTORY / sample["chain"])
    assert len(chain) == 3
    assert [cert.fingerprint(hashes.SHA256()).hex() for cert in chain] == sample[
        "certificate_sha256"
    ]
    leaf = chain[0]
    assert leaf.not_valid_before_utc.isoformat() == sample["not_before"]
    assert leaf.not_valid_after_utc.isoformat() == sample["not_after"]
    assert sample["fulcio"].keys() <= FULCIO_OIDS.keys()

    legacy_issuer = leaf.extensions.get_extension_for_oid(LEGACY_ISSUER_OID)
    assert not legacy_issuer.critical
    assert isinstance(legacy_issuer.value, x509.UnrecognizedExtension)
    assert legacy_issuer.value.value == sample["fulcio_issuer"].encode("utf-8")

    for field, oid in FULCIO_OIDS.items():
        object_identifier = x509.ObjectIdentifier(oid)
        if field not in sample["fulcio"]:
            with pytest.raises(x509.ExtensionNotFound):
                leaf.extensions.get_extension_for_oid(object_identifier)
        else:
            extension = leaf.extensions.get_extension_for_oid(object_identifier)
            assert not extension.critical
            assert isinstance(extension.value, x509.UnrecognizedExtension)
            assert extension.value.value == der_utf8_string(sample["fulcio"][field])

    issuer = sample["fulcio_issuer"]
    assert issuer.startswith("https://")
    san_type, san_value = sample["san"]
    ca_fingerprint = b64url(bytes.fromhex(sample["certificate_sha256"][-1]))
    did = (
        f"did:x509:0:sha256:{ca_fingerprint}"
        f"::fulcio-issuer:{pctencode(issuer[len('https://'):])}"
        f"::san:{san_type}:{pctencode(san_value)}"
    )
    assert resolve_did(did, chain)["id"] == did
