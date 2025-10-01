# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from typing import List
import argparse
import json
import datetime
from base64 import urlsafe_b64encode
from urllib.parse import unquote, quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
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


def parse_extensions(exts: x509.Extensions):
    extensions = {}
    for ext in exts:
        value = ext.value
        if isinstance(value, x509.BasicConstraints):
            # handled by verify_chain
            continue
        elif isinstance(value, x509.KeyUsage):
            # handled by create_did_document
            continue
        elif isinstance(value, x509.ExtendedKeyUsage):
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
                else:
                    raise RuntimeError(f"unsupported SAN: {san}")
        elif ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.1":
            ext_name = "fulcio_issuer"
            assert isinstance(value, x509.UnrecognizedExtension)
            ext_value = value.value.decode("utf-8")
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


def verify_certificate_is_issued_by(
    certificate: x509.Certificate, other: x509.Certificate
):
    if other.subject != certificate.issuer:
        raise RuntimeError(
            "Certificate issuer does not match subject of issuer certificate"
        )
    public_key = other.public_key()
    signature = certificate.signature
    data = certificate.tbs_certificate_bytes
    if isinstance(public_key, rsa.RSAPublicKeyWithSerialization):
        public_key.verify(
            signature,
            data,
            padding=padding.PKCS1v15(),
            algorithm=certificate.signature_hash_algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKeyWithSerialization):
        public_key.verify(
            signature,
            data,
            signature_algorithm=ec.ECDSA(certificate.signature_hash_algorithm),
        )
    else:
        raise NotImplementedError("Unsupported public key type")


def verify_certificate_in_chain(
    chain: List[x509.Certificate], i: int, skip_validity_period_check=False
):
    cert = chain[i]

    if i > 0:
        try:
            bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            pass
        else:
            basic_constraints = bc_ext.value
            if not basic_constraints.ca:
                raise ValueError(f"Certificate {i} basic constraints: CA bit missing")
            if (
                basic_constraints.path_length is not None
                and basic_constraints.path_length > i
            ):
                raise ValueError(
                    f"Certificate {i} basic constraints: path length constraint violated"
                )

    if not skip_validity_period_check:
        now = datetime.datetime.now()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            raise ValueError(f"Certificate {i} is not valid now")


def verify_certificate_chain(
    chain: List[x509.Certificate], skip_validity_period_check=False
):
    if len(chain) < 2:
        raise ValueError("Certificate chain must have at least two certificates")
    for i in range(len(chain) - 1):
        verify_certificate_is_issued_by(chain[i], chain[i + 1])
    for i in range(len(chain)):
        verify_certificate_in_chain(chain, i, skip_validity_period_check)


def check_did_x509(did: str, chain: List[x509.Certificate]):
    decoded = [decode_certificate(cert) for cert in chain]

    prefix = "did:x509:0:"
    if not did.startswith(prefix):
        raise ValueError("invalid did prefix")
    parts = did[len(prefix) :].split("::")
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
            fulcio_issuer = "https://" + pctdecode(value)
            expected_fulcio_issuer = decoded[0]["extensions"]["fulcio_issuer"]
            if fulcio_issuer != expected_fulcio_issuer:
                raise ValueError(
                    f"invalid Fulcio issuer: {pctencode(fulcio_issuer)}, expected: {pctencode(expected_fulcio_issuer)}"
                )

        else:
            raise ValueError(f"unknown did:x509 policy: {name}")


def to_jwk(cert: x509.Certificate) -> dict:
    return jwcrypto.jwk.JWK.from_pyca(cert.public_key()).export_public(as_dict=True)


def create_did_document(did: str, chain: List[x509.Certificate]):
    leaf = chain[0]
    doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "JsonWebKey2020",
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
        doc["assertionMethod"] = [f"{did}#key-1"]
    if include_key_agreement:
        doc["keyAgreement"] = [f"{did}#key-1"]
    if not include_assertion_method and not include_key_agreement:
        raise ValueError(
            "leaf certificate key usage must include digital signature or key agreement"
        )

    return doc


def resolve_did(
    did: str, chain: List[x509.Certificate], skip_validity_period_check=False
) -> dict:
    verify_certificate_chain(chain, skip_validity_period_check)
    check_did_x509(did, chain)
    doc = create_did_document(did, chain)
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
