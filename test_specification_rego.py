# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509

from didx509.didx509 import check_did_x509, decode_certificate
from test_vectors import TEST_VECTORS, load_vector_chain


PERCENT_UTF8_CASES = [
    ("%FF", False), ("%FE", False), ("%80", False), ("%C3", False),
    ("%C0%AF", False), ("%ED%A0%80", False), ("%F4%90%80%80", False),
    ("%F0%9F", False), ("%EF%BF", False), ("%FF%EF%BF%BD", False),
    ("%EF%BF%BD", True), ("%ef%bf%bd", True),
]

# In CI, a missing OPA must fail the run rather than skip these tests.
pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None and "CI" not in os.environ,
    reason="OPA is not installed",
)


@pytest.fixture(scope="module")
def policy_file(tmp_path_factory):
    specification = (Path(__file__).parent / "specification.md").read_text(
        encoding="utf-8"
    )
    blocks = re.findall(
        r"^```rego\n(.*?)^```$", specification, re.MULTILINE | re.DOTALL
    )
    path = tmp_path_factory.mktemp("specification") / "policy.rego"
    path.write_text("".join(blocks), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def policy_package(policy_file):
    package = re.search(
        r"^package\s+(\S+)", policy_file.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert package, "The Rego policy has no package declaration."
    return package[1]


def test_policy_compiles(policy_file):
    result = subprocess.run(
        ["opa", "check", "--strict", str(policy_file)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def evaluate_policy(policy_file, policy_package, did, model):
    result = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--stdin-input",
            "--data",
            str(policy_file),
            f"data.{policy_package}.valid",
        ],
        input=json.dumps({"did": did.split("#", 1)[0], "chain": model}),
        capture_output=True,
        text=True,
        timeout=30,
    )
    # opa eval reports evaluation errors on stdout when using --format json.
    assert result.returncode == 0, result.stdout + result.stderr
    output = json.loads(result.stdout)
    return (
        "result" in output and output["result"][0]["expressions"][0]["value"] is True
    )


@pytest.mark.parametrize(
    "vector",
    [pytest.param(vector, id=vector["id"]) for vector in TEST_VECTORS],
)
def test_policy_matches_implementation(policy_file, policy_package, vector):
    chain = load_vector_chain(vector)
    try:
        model = [decode_certificate(certificate) for certificate in chain]
    except (ValueError, RuntimeError, x509.DuplicateExtension) as e:
        pytest.skip(f"The chain cannot be mapped to the JSON model: {e}")

    did = vector["input"]["did"]
    try:
        check_did_x509(did, chain)
        expected = True
    except ValueError:
        expected = False
    if "document" in vector["output"]:
        assert expected

    assert evaluate_policy(policy_file, policy_package, did, model) == expected


@pytest.mark.parametrize("encoded,expected", PERCENT_UTF8_CASES)
def test_othername_query_unescape_cannot_match_invalid_utf8(
    policy_file, policy_package, encoded, expected
):
    oid = "1.3.6.1.4.1.57264.1.7"
    model = [
        {"extensions": {"san": [
            ["othername", oid, "\ufffd" * count] for count in range(1, 5)
        ]}},
        {"fingerprint": {"sha256": "root"}},
    ]
    did = f"did:x509:0:sha256:root::san:othername:{oid}:{encoded}"
    assert evaluate_policy(policy_file, policy_package, did, model) == expected


@pytest.mark.parametrize("encoded,valid_utf8", PERCENT_UTF8_CASES)
@pytest.mark.parametrize("field,replacements", [
    ("issuer", 1), ("token-subject", 2),
    ("source-repository-uri", 3), ("build-signer-digest", 4),
])
def test_fulcio_query_unescape_cannot_match_invalid_utf8(
    policy_file, policy_package, encoded, valid_utf8, field, replacements
):
    model = [
        {"extensions": {"fulcio": {field: "\ufffd" * replacements}}},
        {"fingerprint": {"sha256": "root"}},
    ]
    did = f"did:x509:0:sha256:root::fulcio:{field}:{encoded}"
    expected = valid_utf8 and replacements == 1
    assert evaluate_policy(policy_file, policy_package, did, model) == expected


@pytest.mark.parametrize("encoded,expected", PERCENT_UTF8_CASES)
def test_invalid_utf8_subject_values_cannot_be_dropped_from_a_predicate(
    policy_file, policy_package, encoded, expected
):
    model = [
        {"subject": {"CN": "Leaf", "O": "\ufffd"}},
        {"fingerprint": {"sha256": "root"}},
    ]
    did = f"did:x509:0:sha256:root::subject:CN:Leaf:O:{encoded}"
    assert evaluate_policy(policy_file, policy_package, did, model) == expected


@pytest.mark.parametrize("field", [
    "username", "Issuer", "%69ssuer", "source_repository_uri",
    "1.3.6.1.4.1.57264.1.8", "8", "othername",
])
def test_unknown_fulcio_fields_fail_even_if_supplied_in_the_json_model(
    policy_file, policy_package, field
):
    model = [
        {"extensions": {"fulcio": {field: "opaque"}}},
        {"fingerprint": {"sha256": "root"}},
    ]
    did = f"did:x509:0:sha256:root::fulcio:{field}:opaque"
    assert not evaluate_policy(policy_file, policy_package, did, model)
