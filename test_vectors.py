# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import base64
import json
from pathlib import Path

import pytest
from cryptography import x509

from didx509.didx509 import resolve_did


with (Path(__file__).parent / "test-vectors.json").open() as vectors_file:
    TEST_VECTORS = json.load(vectors_file)

vector_ids = [vector["id"] for vector in TEST_VECTORS]
if len(vector_ids) != len(set(vector_ids)):
    raise ValueError("test vector IDs must be unique")
for vector in TEST_VECTORS:
    if set(vector) != {"id", "input", "output"}:
        raise ValueError(f"invalid test vector fields: {vector['id']}")
    if set(vector["input"]) != {"did", "chain"}:
        raise ValueError(f"invalid test vector input: {vector['id']}")
    if set(vector["output"]) not in ({"document"}, {"error"}):
        raise ValueError(f"invalid test vector output: {vector['id']}")


def load_vector_chain(vector):
    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    return [
        x509.load_der_x509_certificate(decode(certificate))
        for certificate in vector["input"]["chain"]
    ]


def assert_expected_value(expected, actual, path=()):
    if isinstance(expected, dict):
        if path[-1:] == ("publicKeyJwk",):
            assert actual.keys() - {"kid"} == expected.keys()
        else:
            assert actual.keys() == expected.keys()
        for key, value in expected.items():
            assert key in actual
            assert_expected_value(value, actual[key], (*path, key))
        return
    if isinstance(expected, list):
        assert len(actual) == len(expected)
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            assert_expected_value(expected_item, actual_item, (*path, index))
        return
    assert actual == expected


def check_vector(vector):
    chain = load_vector_chain(vector)
    vector_input = vector["input"]
    expected_output = vector["output"]

    if "error" in expected_output:
        with pytest.raises(ValueError) as exc_info:
            resolve_did(vector_input["did"], chain)
        assert str(exc_info.value) == expected_output["error"]
        return

    document = resolve_did(vector_input["did"], chain)
    assert_expected_value(expected_output["document"], document)


@pytest.mark.parametrize(
    "vector",
    [pytest.param(vector, id=vector["id"]) for vector in TEST_VECTORS],
)
def test_vector(vector):
    check_vector(vector)
