# did:x509

This repository contains the specification of the did:x509 [DID](https://www.w3.org/TR/did-core/) method. It aims to achieve interoperability between existing X.509 solutions and Decentralized Identifiers (DIDs) to support operational models in which a full transition to DIDs is not achievable or desired yet. It is registered as a [DID method](https://w3c.github.io/did-extensions/methods/) with the did-wg in the W3C.

## Specification

See [specification.md](specification.md).

## Reference implementation

This repository contains a non-production reference implementation written in Python.

First, install the required Python packages:

```
pip install -r requirements.txt
```

Then, run the resolver with an example DID and matching certificate chain:

```sh
python -m didx509 resolve did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation --chain test-data/ms-code-signing.pem
# Output: { <DID document> }
```

The reference resolver does not check certificate validity periods. Applications
may validate them at a context-relevant time.

To convert a certificate chain to the JSON data model defined in the specification, run:

```sh
python -m didx509 convert test-data/ms-code-signing.pem
# Output: [ Certificate chain in JSON ]
```

To percent-encode a string for use in policies, run:

```sh
python -m didx509 encode "My Org"
# Output: My%20Org
```

Run tests with:

```
pytest -v
```

The Rego policy in the specification is also checked against the test vectors when [OPA](https://www.openpolicyagent.org/) is installed; those tests are skipped otherwise.

The `san` predicate also supports
`::san:othername:1.3.6.1.4.1.57264.1.7:alice%21example.com`.
The closed OtherName registry currently contains only this Fulcio username type,
encoded as a strict DER UTF8String inside the SAN extension. `convert` preserves
its OID and full identity as
`["othername", "1.3.6.1.4.1.57264.1.7", "alice!example.com"]`; it does not infer
the identity from standalone Fulcio extensions. Critical SANs still undergo
normal RFC 5280 path validation.

Valid registered OtherName SANs are now accepted even when an existing predicate
is selected. Unregistered or malformed OtherNames and other unsupported SAN
forms still fail. Existing SAN pairs and DID Documents are unchanged; older
method-0 resolvers reject the new selector. The synthetic OtherName test vectors
are signed independently of the real certificate fixtures.

Real Fulcio certificate chains and expected extension values are kept separately
in [test-data/fulcio-issuer-v2/manifest.json](test-data/fulcio-issuer-v2/manifest.json).
The `fulcio` predicate supports all 17 registered standalone fields `.8`-`.24`,
for example:

```sh
python -m didx509 resolve did:x509:0:sha256:O6e2zE6VRp1NM0tJyyV62FNwdvqEsMqH_07P5qVGgME::fulcio:issuer:https%3A%2F%2Ftoken.actions.githubusercontent.com::fulcio:deployment-environment:release::fulcio:token-subject:repo%3Apydantic%2Fpydantic-ai%3Aenvironment%3Arelease --chain test-data/fulcio-issuer-v2/pydantic-ai-2.54.0.pem
```

Each predicate requires one literal registered field and one nonempty
percent-encoded scalar; multiple predicates are ANDed. `convert` maps present
fields to `extensions.fulcio`, decoding strict DER UTF8Strings eagerly.
Malformed registered values and critical standalone Fulcio extensions fail even
when not selected. Missing fields fail; no fields are inferred or required
unless selected. Values are exact opaque strings, with no URI, digest, numeric,
or provider-specific normalization. Encode a colon as `%3A` and a literal percent
as `%25`; an existing URI escape `%2F` therefore becomes `%252F`.

Issuer migration changes the DID explicitly. `::fulcio-issuer:issuer.example.com`
still selects only raw UTF-8 `.1` in `extensions.fulcio_issuer`, using the existing
HTTPS-suffix comparison. `::fulcio:issuer:https%3A%2F%2Fissuer.example.com` selects
only Issuer V2 (`.8`) in `extensions.fulcio.issuer`, comparing the full string.
There is no fallback, alias, agreement check, or rewrite between them. Older
method-0 resolvers reject the new predicate. The [C++ tracking issue,
microsoft/didx509cpp#74](https://github.com/microsoft/didx509cpp/issues/74), is
separate from this Python implementation.

Offline implementation tests exercise every selector against the unchanged
production pydantic-ai chain. The sigstore-js-2026-08-04 chain supplies a token
subject but no deployment environment; token-subject absence is covered by
independently signed synthetic chains, alongside V2-only, differing dual issuers,
strict encoding and path-validation cases.

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
