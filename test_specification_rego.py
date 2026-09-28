# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from didx509.didx509 import check_did_x509, decode_certificate
from test_vectors import TEST_VECTORS, load_vector_chain


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


@pytest.mark.parametrize(
    "vector",
    [pytest.param(vector, id=vector["id"]) for vector in TEST_VECTORS],
)
def test_policy_matches_implementation(policy_file, policy_package, vector):
    chain = load_vector_chain(vector)
    try:
        model = [decode_certificate(certificate) for certificate in chain]
    except (ValueError, RuntimeError) as e:
        pytest.skip(f"The chain cannot be mapped to the JSON model: {e}")

    did = vector["input"]["did"]
    try:
        check_did_x509(did, chain)
        expected = True
    except ValueError:
        expected = False
    if "document" in vector["output"]:
        assert expected

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
    valid = (
        "result" in output and output["result"][0]["expressions"][0]["value"] is True
    )
    assert valid == expected
