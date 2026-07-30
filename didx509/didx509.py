# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import List
import argparse
import json
from base64 import urlsafe_b64encode
from urllib.parse import unquote, quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from OpenSSL import crypto
import jwcrypto.jwk


NAME_OID_STRINGS = {
    # https://datatracker.ietf.org/doc/html/rfc4514.html
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.6": "C",
    "2.5.4.9": "STREET",
}


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).decode().rstrip("=")


def pctencode(data: str) -> str:
    return quote(data, safe="").replace("~", "%7E")


def pctdecode(data: str) -> str:
    return unquote(data)


def parse_name(name: x509.Name) -> dict:
    oids = [item.oid for item in name]
    if len(oids) != len(set(oids)):
        raise ValueError("duplicates not allowed")

    items = {}
    for attribute in name:
        oid = attribute.oid.dotted_string
        if oid in NAME_OID_STRINGS:
            items[NAME_OID_STRINGS[oid]] = attribute.value
        else:
            items[oid] = attribute.value
    return items


FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.1"

# Critical extensions that the specification requires resolution to tolerate,
# beyond those represented in the JSON model. Path validation enforces them.
PERMITTED_CRITICAL_EXTENSION_OIDS = {
    "2.5.29.19",  # basicConstraints
    "2.5.29.15",  # keyUsage
    "2.5.29.30",  # nameConstraints
    "2.5.29.36",  # policyConstraints
    "2.5.29.33",  # policyMappings
    "2.5.29.32",  # certificatePolicies
    "2.5.29.54",  # inhibitAnyPolicy
}


def parse_extensions(exts: x509.Extensions):
    extensions = {}
    for ext in exts:
        value = ext.value
        if isinstance(value, x509.ExtendedKeyUsage):
            ext_name = "eku"
            ext_value = []
            for eku in value:
                oid = eku.dotted_string
                ext_value.append(oid)
        elif isinstance(value, x509.SubjectAlternativeName):
            ext_name = "san"
            ext_value = []
            for san in value:
                if isinstance(san, x509.RFC822Name):
                    ext_value.append(["email", san.value])
                elif isinstance(san, x509.DNSName):
                    ext_value.append(["dns", san.value])
                elif isinstance(san, x509.UniformResourceIdentifier):
                    ext_value.append(["uri", san.value])
                elif isinstance(san, x509.DirectoryName):
                    ext_value.append(["dn", parse_name(san.value)])
                    raise ValueError(f"unsupported SAN: {san}")
        elif ext.oid.dotted_string == FULCIO_ISSUER_OID:
            ext_name = "fulcio_issuer"
            assert isinstance(value, x509.UnrecognizedExtension)
            ext_value = value.value.decode("utf-8")
        elif ext.oid.dotted_string in PERMITTED_CRITICAL_EXTENSION_OIDS:
            continue
        elif not ext.critical:
            continue
        else:
            raise RuntimeError(f"unsupported critical extension: {ext}")
        extensions[ext_name] = ext_value
    return extensions


def decode_certificate(c: x509.Certificate) -> dict:
    exts = parse_extensions(c.extensions)
    return {
        "fingerprint": {
            "sha256": b64url(c.fingerprint(hashes.SHA256())),
            "sha384": b64url(c.fingerprint(hashes.SHA384())),
            "sha512": b64url(c.fingerprint(hashes.SHA512())),
        },
        "issuer": parse_name(c.issuer),
        "subject": parse_name(c.subject),
        "extensions": exts,
    }


def load_certificate(path) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_certificate_chain(path) -> List[x509.Certificate]:
    sep = "-----END CERTIFICATE-----"
    with open(path, "r") as f:
        chain = [
            x509.load_pem_x509_certificate((d + sep).encode())
            for d in f.read().split(sep)
            if d.strip()
        ]
    return chain


# Not exposed by pyOpenSSL's X509StoreFlags. Defined in OpenSSL's x509_vfy.h.
X509_V_FLAG_NO_CHECK_TIME = 0x200000


def verify_certificate_chain(
    chain: List[x509.Certificate], skip_validity_period_check=False
):
    """Perform RFC 5280 certification path validation on a leaf-first chain.

    The last certificate in the chain is used as the trust anchor, as required
    by the did:x509 specification. Validation is delegated to OpenSSL so that
    the full RFC 5280 algorithm applies, including basic constraints, path
    length constraints, key usage, name constraints, and validity periods.

    skip_validity_period_check suppresses the validity period check at every
    depth, for testing against expired certificates.

    Deciding whether the trust anchor itself is acceptable is out of scope; the
    specification leaves that to relying-party policy.

    Critical-extension processing is left to OpenSSL, which rejects any critical
    extension it does not recognize. The fulcio_issuer extension is unrecognized
    and must not be marked critical, so this is the behaviour the specification
    requires. parse_extensions permits the standard critical extensions the
    specification allows, which OpenSSL recognizes and processes here.
    """
    if len(chain) < 2:
        raise ValueError("Certificate chain must have at least two certificates")

    flags = (
        # Any certificate in the store may act as a trust anchor, so a chain
        # ending at an intermediate is accepted.
        crypto.X509StoreFlags.PARTIAL_CHAIN
        # Verify the trust anchor's own signature when it is self-signed.
        | crypto.X509StoreFlags.CHECK_SS_SIGNATURE
    )
    if skip_validity_period_check:
        flags |= X509_V_FLAG_NO_CHECK_TIME

    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(chain[-1]))
    store.set_flags(flags)

    ctx = crypto.X509StoreContext(
        store,
        crypto.X509.from_cryptography(chain[0]),
        chain=[crypto.X509.from_cryptography(cert) for cert in chain[1:-1]],
    )
    try:
        ctx.verify_certificate()
    except crypto.X509StoreContextError as e:
        raise ValueError(f"certificate chain verification failed: {e}") from e


def check_did_x509(did: str, chain: List[x509.Certificate]) -> str:
    decoded = [decode_certificate(cert) for cert in chain]

    prefix = "did:x509:0:"
    did_document_id = did.split("#", 1)[0]
    if not did_document_id.startswith(prefix):
        raise ValueError("invalid did prefix")
    query_index = did_document_id.find("?")
    path_index = did_document_id.find("/")
    if path_index != -1 and (query_index == -1 or path_index < query_index):
        raise ValueError("DID URL path is not supported")
    if query_index != -1:
        raise ValueError("DID URL query is not supported")
    parts = did_document_id[len(prefix) :].split("::")
    [ca_fingerprint_alg, ca_fingerprint] = parts[0].split(":")
    policies = [p.split(":", 1) for p in parts[1:]]
    if len(policies) == 0:
        raise ValueError("no policies specified")

    expected_ca_fingerprints = [
        c["fingerprint"][ca_fingerprint_alg] for c in decoded[1:]
    ]
    if ca_fingerprint not in expected_ca_fingerprints:
        raise ValueError(
            f"invalid CA fingerprint, expected one of: {expected_ca_fingerprints}"
        )

    for [name, value] in policies:
        if name == "subject":
            parts = value.split(":")
            if not parts or len(parts) % 2 != 0:
                raise ValueError("key-value pairs required")
            fields = list(zip(parts[::2], parts[1::2]))
            if len(fields) != len(set(fields)):
                raise ValueError("duplicate subject fields")
            for key, value in fields:
                if key not in decoded[0]["subject"]:
                    raise ValueError(f"invalid subject key: {key}")
                value = pctdecode(value)
                expected_value = decoded[0]["subject"][key]
                if value != expected_value:
                    raise ValueError(
                        f"invalid subject value: {key} = {pctencode(value)}, expected: {pctencode(expected_value)}"
                    )

        elif name == "san":
            parts = value.split(":")
            if len(parts) != 2:
                raise ValueError("exactly one SAN type and value required")
            san_type = parts[0]
            san_value = pctdecode(parts[1])
            san = [san_type, san_value]
            sans = decoded[0]["extensions"]["san"]
            if san not in sans:
                raise ValueError(f"invalid SAN: {san}, expected one of: {sans}")

        elif name == "eku":
            if "eku" not in decoded[0]["extensions"]:
                raise ValueError("no EKU extension in certificate")
            eku = value
            ekus = decoded[0]["extensions"]["eku"]
            if eku not in ekus:
                raise ValueError(f"invalid EKU: {eku}, expected one of: {ekus}")

        elif name == "fulcio-issuer":
            if "fulcio_issuer" not in decoded[0]["extensions"]:
                raise ValueError("no Fulcio issuer extension in certificate")
            fulcio_issuer = "https://" + pctdecode(value)
            expected_fulcio_issuer = decoded[0]["extensions"]["fulcio_issuer"]
            if fulcio_issuer != expected_fulcio_issuer:
                raise ValueError(
                    f"invalid Fulcio issuer: {pctencode(fulcio_issuer)}, expected: {pctencode(expected_fulcio_issuer)}"
                )

        else:
            raise ValueError(f"unknown did:x509 policy: {name}")

    return did_document_id


def to_jwk(cert: x509.Certificate) -> dict:
    return jwcrypto.jwk.JWK.from_pyca(cert.public_key()).export_public(as_dict=True)


def create_did_document(did: str, chain: List[x509.Certificate]):
    leaf = chain[0]
    doc = {
        "@context": "https://www.w3.org/ns/cid/v1",
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#0",
                "type": "JsonWebKey",
                "controller": did,
                "publicKeyJwk": to_jwk(leaf),
            }
        ],
    }

    try:
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None

    include_assertion_method = key_usage is None or key_usage.digital_signature
    include_key_agreement = key_usage is None or key_usage.key_agreement
    if include_assertion_method:
        doc["authentication"] = [f"{did}#0"]
        doc["assertionMethod"] = [f"{did}#0"]
    if include_key_agreement:
        doc["keyAgreement"] = [f"{did}#0"]
    if not include_assertion_method and not include_key_agreement:
        raise ValueError(
            "leaf certificate key usage must include digital signature or key agreement"
        )

    return doc


def resolve_did(
    did: str, chain: List[x509.Certificate], skip_validity_period_check=False
) -> dict:
    verify_certificate_chain(chain, skip_validity_period_check)
    did_document_id = check_did_x509(did, chain)
    doc = create_did_document(did_document_id, chain)
    return doc


def cli_resolve(did: str, chain_path: str, skip_validity_period_check: bool):
    chain = load_certificate_chain(chain_path)
    doc = resolve_did(did, chain, skip_validity_period_check)
    print(json.dumps(doc, indent=2))


def cli_convert(chain_path: str):
    chain = load_certificate_chain(chain_path)
    decoded = [decode_certificate(cert) for cert in chain]
    print(json.dumps(decoded, indent=2))


def cli_encode(s: str):
    print(pctencode(s))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd")

    p = subparsers.add_parser("resolve")
    p.add_argument("did", help="The DID to resolve")
    p.add_argument(
        "--chain", required=True, help="Path to the certificate chain in PEM format"
    )
    p.add_argument(
        "--skip-validity-period-check", action="store_true", help="Testing only."
    )
    p.set_defaults(
        func=lambda args: cli_resolve(
            args.did, args.chain, args.skip_validity_period_check
        )
    )

    p = subparsers.add_parser("convert")
    p.add_argument("chain", help="Path to the certificate chain in PEM format")
    p.set_defaults(func=lambda args: cli_convert(args.chain))

    p = subparsers.add_parser("encode")
    p.add_argument("string", help="The string to percent-encode")
    p.set_defaults(func=lambda args: cli_encode(args.string))

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
