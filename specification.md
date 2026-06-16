# did:x509 Method Specification

## Status, Version, and Authors

Status: DRAFT

Method version: `0`

Authors:
- Maik Riechert (Microsoft)
- Antoine Delignat-Lavaud (Microsoft)

## Abstract

This draft aims to define an interoperable and flexible issuer identifier format for messages that transport or refer to X.509 certificates, including COSE messages using [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360).
The did:x509 identifier format implements a direct, resolvable binding between a certificate chain and a compact issuer string.
It can be conveyed as an issuer value in a COSE Header CWT Claims map as defined in [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597), in JOSE/JWT messages such as the `iss` claim defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), or through other protocol-specific mechanisms that associate the identifier with the certificate chain.
This issuer identifier is convenient for references and policy evaluation, for example in the context of transparency ledgers.

## Introduction

The RWOT11 workshop outlined the need for hybrid solutions that combine X.509 certificates with DIDs: ["Analysis of hybrid wallet solutions - Implementation options for combining x509 certificates with DIDs and VCs"](https://github.com/WebOfTrustInfo/rwot11-the-hague/blob/master/advance-readings/hybrid_wallet_solutions_x509_DIDs_VCs.md).

The did:x509 method takes a simple approach that does not introduce additional infrastructure. Creating and resolving a did:x509 is a local operation. It relies on X.509 chain validation and matches elements contained in the DID to certificate properties within the chain.

The main difference to other DID methods is that did:x509 requires a certificate chain to be passed using a new [DID resolution option](https://www.w3.org/TR/did-core/#did-resolution-options) `x509chain` while resolving a DID. This certificate chain is typically embedded in the signing envelope, for example within the `x5c` header parameter of JWS/JWT documents.

Embedding certificate chains in configuration or policy is cumbersome. References to individual chain elements can also be too broad, or too unstable when those elements are short-lived.

did:x509 combines authority pinning with certificate predicates in a compact identifier, for example `request.issuer == "did:x509:..."`.

## DID Method Name

The DID method name is `x509`.

A did:x509 DID starts with `did:x509:` and binds a CA fingerprint to one or more certificate predicates.

## DID Syntax

The did:x509 ABNF definitions use [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234.html). The DID Core `idchar` and `pct-encoded` definitions are repeated for readability.

```abnf
idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
pct-encoded        = "%" HEXDIG HEXDIG
```

```abnf
did-x509           = "did:x509:" method-specific-id
method-specific-id = version ":" ca-fingerprint-alg ":" ca-fingerprint 1*("::" predicate-name ":" predicate-value)
version            = 1*DIGIT
ca-fingerprint-alg = "sha256" / "sha384" / "sha512"
ca-fingerprint     = base64url
predicate-name     = "subject" / "san" / "eku" / "fulcio-issuer"
predicate-value    = *(1*idchar ":") 1*idchar
base64url          = 1*(ALPHA / DIGIT / "-" / "_")
```

The current version value is `0`.

The `ca-fingerprint-alg` value is one of `sha256`, `sha384`, or `sha512`. The `ca-fingerprint` value is a base64url-encoded digest of a non-leaf certificate in the certificate chain, that is, either an intermediate or root CA certificate.

The `::` separator introduces predicates. Each predicate has a `predicate-name` and a predicate-specific `predicate-value`.

## Method-specific Identifier

The method-specific identifier has three parts:

1. A version number.
2. A certificate authority fingerprint algorithm and value.
3. One or more predicates that match fields in the leaf certificate.

did:x509 does not define any DID URL path or query semantics. A did:x509 DID URL MUST NOT include a path or query component. Fragment identifiers remain valid for identifying resources within a resolved DID document, for example `<DID>#0`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:Example%20Organisation`

In this example, the identifier pins to a certificate authority using a SHA-256 certificate hash and uses the `subject` predicate to express criteria that a leaf certificate subject must fulfil. This identifier will match certificate chains with matching leaf certificate subject fields and a matching intermediate or root CA certificate.

### Predicate validation model

Predicate validation is defined in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) to avoid ambiguous pseudo-code. Implementations do not have to use Rego.

For the reference Rego, pass the DID string and parsed certificate-chain JSON as:

```json
{
  "did": "<DID>",
  "chain": [
    {
      "fingerprint": {
        "sha256": "<leaf-sha256>"
      },
      "subject": {
        "CN": "Example"
      },
      "extensions": {}
    },
    {
      "fingerprint": {
        "sha256": "<ca-sha256>"
      },
      "subject": {
        "CN": "Example CA"
      },
      "extensions": {}
    }
  ]
}
```

Here, `chain` is derived from the `x509chain` resolution option.

Core Rego policy:

```rego
import future.keywords.if
import future.keywords.in

parse_did(did) :=
  [ca_fingerprint_alg, ca_fingerprint, predicates] if {
    prefix := "did:x509:0:"
    startswith(did, prefix) == true
    rest := trim_prefix(did, prefix)
    parts := split(rest, "::")
    [ca_fingerprint_alg, ca_fingerprint] := split(parts[0], ":")
    predicates_raw := array.slice(parts, 1, count(parts))
    predicates := [y |
        some i
        s := predicates_raw[i]
        j := indexof(s, ":")
        y := [substring(s, 0, j), substring(s, j+1, -1)]
    ]
}

valid if {
    [ca_fingerprint_alg,
     ca_fingerprint,
     predicates] := parse_did(input.did)
    ca := [c | some i; i != 0; c := input.chain[i]]
    ca[_].fingerprint[ca_fingerprint_alg] == ca_fingerprint
    valid_predicates := [i |
        some i
        [name, value] := predicates[i]
        validate_predicate(name, value)
    ]
    count(valid_predicates) == count(predicates)
}
```

The overall Rego policy is assembled by concatenating the core Rego policy with the Rego policy fragments in the following sections, each one defining a `validate_predicate` function.

### Percent-encoding

Some predicates require values to be percent-encoded. Percent-encoding is specified in [RFC 3986 Section 2.1](https://www.rfc-editor.org/rfc/rfc3986#section-2.1). All characters that are not in the allowed set below must be percent-encoded:

```abnf
allowed = ALPHA / DIGIT / "-" / "." / "_"
```

Note that most libraries implement percent-encoding in the context of URLs and do not encode `~` (`%7E`).

### `subject` predicate

```abnf
predicate-name     = "subject"
predicate-value    = key ":" value *(":" key ":" value)
key                = label / oid
value              = 1*idchar
label              = "CN" / "L" / "ST" / "O" / "OU" / "C" / "STREET"
oid                = 1*DIGIT *("." 1*DIGIT)
```

`<key>:<value>` are the subject name fields in `chain[0].subject` in any order. Key repetitions are not allowed. Values must be percent-encoded.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:Example%20Organisation`

Rego policy:

```rego
validate_predicate(name, value) := true if {
    name == "subject"
    items := split(value, ":")
    count(items) % 2 == 0
    subject := {k: v |
        some i
        i % 2 == 0
        k := items[i]
        v := urlquery.decode(items[i+1])
    }
    count(subject) >= 1
    count(subject) == count(items) / 2
    object.subset(input.chain[0].subject, subject) == true
}
```

### `san` predicate

```abnf
predicate-name     = "san"
predicate-value    = san-type ":" san-value
san-type           = "email" / "dns" / "uri"
san-value          = 1*idchar
```

`san-type` is the SAN type and must be one of `email`, `dns`, or `uri`. Note that `dn` is not supported. `san-value` is percent-encoded. The pair [`<san_type>`, `<san_value>`] is one of the items in `chain[0].extensions.san`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email:bob%40example.com`

Rego policy:

```rego
validate_predicate(name, value) := true if {
    name == "san"
    [san_type, san_value_encoded] := split(value, ":")
    san_value := urlquery.decode(san_value_encoded)
    [san_type, san_value] == input.chain[0].extensions.san[_]
}
```

### `eku` predicate

```abnf
predicate-name     = "eku"
predicate-value    = eku
eku                = oid
oid                = 1*DIGIT *("." 1*DIGIT)
```

`eku` is one of the OIDs within `chain[0].extensions.eku`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13`

Rego policy:

```rego
validate_predicate(name, value) := true if {
    name == "eku"
    value == input.chain[0].extensions.eku[_]
}
```

### `fulcio-issuer` predicate

```abnf
predicate-name     = "fulcio-issuer"
predicate-value    = fulcio-issuer
fulcio-issuer      = 1*idchar
```

`fulcio-issuer` is `chain[0].extensions.fulcio_issuer`, without leading `https://`, percent-encoded.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:accounts.google.com::san:email:bob%40example.com`

Example 2:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:issuer.example.com::san:uri:https%3A%2F%2Fexample.com%2Focto-org%2Focto-automation%2Fworkflows%2Foidc.yml%40refs%2Fheads%2Fmain`

Rego policy:

```rego
validate_predicate(name, value) := true if {
    name == "fulcio-issuer"
    suffix := urlquery.decode(value)
    concat("", ["https://", suffix]) == input.chain[0].extensions.fulcio_issuer
}
```

## Verifiable Data Registry and Trust Model

did:x509 does not define a persistent registry of DID Documents. Resolution uses the DID string and the `x509chain` resolution option.

The `x509chain` option carries the certificate chain as a comma-separated list of base64url-encoded DER certificates:

```text
x509chain = b64url(DER(leaf)) "," b64url(DER(intermediate)) "," b64url(DER(root))
```

The chain is ordered leaf first and root or trust anchor last. Each comma-separated item is the DER encoding of one complete X.509 certificate, not a public key, fingerprint, or DER encoding of the whole chain.

Trust is established by validating the certificate chain, matching the CA fingerprint, and validating the predicates against the leaf certificate. Applications can add revocation, certificate transparency, signing time, or endorsement checks.

## Certificate Chain JSON Model

For predicate evaluation, the resolver maps the certificate chain to a small JSON model. This model contains only the fields did:x509 matches on; it does not replace X.509 parsing or RFC 5280 path validation.

The model is a JSON array with at least two certificate objects. The leaf certificate is first, followed by issuer certificates, with the root or trust anchor last.

Each certificate object can contain:

| Field | Meaning |
|---|---|
| `fingerprint` | Base64url-encoded hashes of the DER-encoded certificate, keyed by `sha256`, `sha384`, and `sha512`. |
| `issuer` | X.509 issuer name, represented as an object of name attributes. |
| `subject` | X.509 subject name, represented as an object of name attributes. |
| `extensions.eku` | Extended Key Usage OIDs from RFC 5280 Section 4.2.1.12. |
| `extensions.san` | Subject Alternative Name entries from RFC 5280 Section 4.2.1.6. |
| `extensions.fulcio_issuer` | The Fulcio issuer extension value. |

Name objects use the RFC 4514 labels `CN`, `L`, `ST`, `O`, `OU`, `C`, and `STREET` for common attributes. Other attributes use dotted OID strings as keys. Repeated attributes are not supported. Values are converted to UTF-8 strings.

SAN entries are arrays. The first item identifies the SAN type, and the second item is the value:

| SAN type | JSON shape |
|---|---|
| RFC 822 name | `["email", "user@example.com"]` |
| DNS name | `["dns", "example.com"]` |
| URI | `["uri", "https://example.com"]` |
| Directory name | `["dn", {"CN": "Example"}]` |

Example certificate chain model:

```json
[
  {
    "fingerprint": {
      "sha256": "leaf-sha256",
      "sha384": "leaf-sha384",
      "sha512": "leaf-sha512"
    },
    "issuer": {
      "CN": "Example CA"
    },
    "subject": {
      "CN": "Example"
    },
    "extensions": {
      "eku": ["1.3.6.1.4.1.311.10.3.13"],
      "san": [
        ["email", "user@example.com"],
        ["dns", "example.com"],
        ["uri", "https://example.com"],
        [
          "dn",
          {
            "CN": "Example"
          }
        ]
      ],
      "fulcio_issuer": "https://issuer.example.com"
    }
  },
  {
    "fingerprint": {
      "sha256": "ca-sha256",
      "sha384": "ca-sha384",
      "sha512": "ca-sha512"
    },
    "issuer": {
      "CN": "Example Root CA"
    },
    "subject": {
      "CN": "Example CA"
    },
    "extensions": {}
  }
]
```

In the rest of this document, `chain` refers to the certificate chain mapped to this JSON model.

## DID Document Shape

Resolving a did:x509 identifier produces a DID Document with a `JsonWebKey` verification method derived from the leaf certificate public key.

If the leaf certificate has the key usage bit for `digitalSignature`, or is missing the key usage extension, the DID Document includes `authentication` and `assertionMethod`. If the leaf certificate has the key usage bit for `keyAgreement`, or is missing the key usage extension, the DID Document includes `keyAgreement`. If the leaf certificate includes the key usage extension but has neither `digitalSignature` nor `keyAgreement`, resolution fails.

Resolvers can use the registered `application/did` media type, and may also support `application/did+ld+json` or `application/did+json` for compatibility with DID Core 1.0 tooling. The media type is selected by the resolution request, not by the DID string.

The JSON-LD `@context` must define every term used. The example below uses the [Controlled Identifiers v1 context](https://www.w3.org/ns/cid/v1).

Example DID Document:

```json
{
  "@context": "https://www.w3.org/ns/cid/v1",
  "id": "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example",
  "verificationMethod": [
    {
      "id": "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example#0",
      "type": "JsonWebKey",
      "controller": "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "usNb0QXAk6R76GPFvKT5a46LC0_qRpxNoLn9WAX8K0I",
        "y": "dTtI2j8aV0Mdk5fNWP9rCJvFIo6QfLjCm8V5v10J4Xg"
      }
    }
  ],
  "authentication": [
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example#0"
  ],
  "assertionMethod": [
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example#0"
  ],
  "keyAgreement": [
    "did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Example#0"
  ]
}
```

## Method Operations

### Create

Creating a did:x509 identifier is a local operation. The DID must be constructed according to the syntax rules in this specification. No registration action is required.

When constructing a did:x509 identifier, determine what constitutes a logical identity within a given certificate authority. Concretely, determine which certificate fields the authority uses to uniquely represent an identity. After that, choose one or more matching predicates that express such an identity as faithfully as possible.

As an example, a certificate authority may use email addresses as a way to separate identities and use the SAN extension to store the email address. In that case, the did:x509 identifier should be constructed using the `san` predicate, for example, `did:x509:0:sha256:<ca-fingerprint>::san:email:bob%40example.com`.

In other cases, an authority may not include email addresses at all and instead rely on a specific set of subject fields to separate identities. In that case, the `subject` predicate should be used.

In yet other cases, authorities may assign unique numbers or other types of stable identifiers to logical identities. Typically, this is done to have a stable reference even if a person changes their name or email address.

In all cases, the goal is to craft a did:x509 identifier that is stable yet not too loose in its predicates. An example of a loose did:x509 identifier may be to use the `subject` predicate and only include the `O` field without location fields like country (`C`) or state/locality (`ST`).

Whether a did:x509 identifier should pin to an intermediate CA instead of a root CA depends on whether there is value in distinguishing between them. Pinning to an intermediate CA typically means that the lifetime of the did:x509 identifier will be shorter, since intermediate CA certificates typically have a shorter validity period than root CA certificates.

### Read / Resolve

The Read operation is DID resolution. The operation takes as input a DID to resolve, together with the `x509chain` DID resolution option.

The DID resolver uses the DID, the certificate chain, and the process in the DID Resolution section to generate a DID Document.

### Update

This DID method does not support updating the DID Document, assuming a fixed certificate chain.

However, the public key included in the DID Document varies depending on the certificate chain that was used as input to the DID resolution process. Typically, multiple chains, in particular leaf certificates, are valid for a given did:x509 identifier.

### Deactivate

This DID method does not support deactivating the DID.

However, if the certificate authority revokes all certificates for the matching DID, or they expire, and does not issue new certificates matching the same DID, then this can be considered equivalent to deactivation of the DID. There is no technical guarantee in this case and the certificate authority can revert its decision.

## DID Resolution

The following steps must be used to generate a corresponding DID Document:

1. Decode the `x509chain` resolution option value into individual certificates by splitting the string on `","` and base64url-decoding each resulting string. The result is a list of DER-encoded certificates that can be loaded in standard libraries. Fail if the list contains fewer than two certificates.

2. Check whether the list of certificates forms a valid certificate chain using [RFC 5280 certification path validation](https://www.rfc-editor.org/rfc/rfc5280#section-6) procedures with the last certificate in the chain as trust anchor. Implementations MUST perform RFC 5280 certification path validation, except that they MUST treat the `fulcio_issuer` extension as recognized for purposes of critical-extension processing. Additionally, fail if any certificate in the chain contains a critical extension that is neither (a) one of the extensions represented in the JSON model (`eku`, `san`, `fulcio_issuer`), nor (b) one of the following standard RFC 5280 extensions: `basicConstraints`, `keyUsage`, `nameConstraints`, `policyConstraints`, `policyMappings`, `certificatePolicies`, `inhibitAnyPolicy`.

3. If required by the application, check whether any certificate in the chain is revoked using CRL, OCSP, or other mechanisms.

4. Apply any further application-specific checks, for example disallowing insecure certificate signature algorithms.

5. Map the certificate chain to the JSON model.

6. Check whether the DID is valid against the certificate chain in the JSON model according to the Rego policy or equivalent rules defined in this document.

7. Extract the public key of the first certificate in the chain.

8. Convert the public key to a JSON Web Key.

9. Create the following partial DID Document:

```json
{
  "@context": "https://www.w3.org/ns/cid/v1",
  "id": "<DID>",
  "verificationMethod": [{
    "id": "<DID>#0",
    "type": "JsonWebKey",
    "controller": "<DID>",
    "publicKeyJwk": {
      "kty": "<JWK key type>"
    }
  }]
}
```

10. If the first certificate in the chain has the key usage bit position for `digitalSignature` set or is missing the key usage extension, add the following to the DID Document:

```json
{
  "authentication": ["<DID>#0"],
  "assertionMethod": ["<DID>#0"]
}
```

11. If the first certificate in the chain has the key usage bit position for `keyAgreement` set or is missing the key usage extension, add the following to the DID Document:

```json
{
  "keyAgreement": ["<DID>#0"]
}
```

12. If the first certificate in the chain includes the key usage extension but has neither `digitalSignature` nor `keyAgreement` set as key usage bits, fail.

13. Return the complete DID Document.

## Security Considerations

### Identifier ambiguity

This DID method maps characteristics of X.509 certificate chains to identifiers. It allows a single identifier to map to multiple certificate chains, giving the identifier stability across the expiry of individual chains. However, if the predicates used in the identifier are chosen too loosely, the identifier may match too wide a set of certificate chains. This may have security implications as it may authorize an identity for actions it was not meant to be authorized for.

To mitigate this issue, the certificate authority should publish their expected usage of certificate fields and indicate which ones constitute a unique identity, versus any additional fields that may be of an informational nature. This will help users create an appropriate did:x509 identifier as well as consumers of signed content to decide whether it is appropriate to trust a given did:x509 identifier.

### X.509 trust stores

Typically, a verifier trusts an X.509 certificate by applying [chain validation](https://www.rfc-editor.org/rfc/rfc5280#section-6) using a set of certificate authority certificates as trust store, together with additional application-specific policies.

This DID method does not require an X.509 trust anchor store but rather relies on verifiers either trusting an individual DID directly or using third-party endorsements for a given DID, like [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/), to establish trust.

By layering this DID method on top of X.509, verifiers are free to use traditional chain validation, for example verifiers unaware of DID, or rely on DID as an ecosystem to establish trust.

### Use of identifier contents

While it is acceptable to use a did:x509 identifier as an opaque handle when it has been endorsed through an external trust mechanism, such as a verifiable credential or a trusted registry, implementers MUST NOT parse or interpret individual components of the identifier string for authorization decisions unless the identifier has been resolved against a verified certificate chain.

Specifically, extracting and relying upon subject names, organizational information, or other embedded values directly from the identifier string, without performing full resolution and chain validation, is insecure. An attacker could craft a syntactically valid did:x509 identifier containing arbitrary values that do not correspond to any legitimate certificate chain. Only after successful resolution, which includes verification of the CA fingerprint against the provided chain and validation of all predicates, can the identifier be considered authentic. Systems that bypass this resolution process and instead parse identifier components directly are vulnerable to impersonation and privilege escalation attacks.

## Privacy Considerations

The did:x509 identifier can contain certificate subject names, subject alternative names, extended key usage values, Fulcio issuer values, and a certificate authority fingerprint. These values can reveal personal names, email addresses, domain names, organizational affiliations, credential issuers, or other identifying information. DID creators should choose predicates that are specific enough for relying-party policy but disclose no more certificate attributes than necessary.

The `x509chain` resolution option carries the certificate chain used as resolution evidence. Certificates can contain additional metadata beyond the predicates encoded in the DID, including subject attributes, SAN entries, validity periods, certificate policies, and extension values. Resolvers and verifiers should treat certificate chains as potentially identifying data, avoid unnecessary logging or redistribution, and apply data minimization when retaining resolution inputs or outputs.

Stable did:x509 identifiers can enable correlation across transactions, transparency logs, ledgers, and verifiable credentials. If unlinkability is required, relying parties should avoid reusing the same did:x509 identifier across contexts, and issuers should prefer predicates based on role- or service-specific identifiers rather than human-identifying certificate fields.

## Examples and Test Vectors

Example subject-based DID:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:Example%20Organisation`

Example SAN-based DID:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email:bob%40example.com`

Example Fulcio-based DID:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:issuer.example.com::san:uri:https%3A%2F%2Fexample.com%2Focto-org%2Focto-automation%2Fworkflows%2Foidc.yml%40refs%2Fheads%2Fmain`

## References

### Normative references

[Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/2022/REC-did-core-20220719/). Manu Sporny, Amy Guy, Markus Sabadello, Drummond Reed. W3C. 19 July 2022. W3C Recommendation.

[RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://www.rfc-editor.org/rfc/rfc5280). D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley, W. Polk. IETF. May 2008. Proposed Standard.

[RFC 4514 - Lightweight Directory Access Protocol (LDAP): String Representation of Distinguished Names](https://www.rfc-editor.org/rfc/rfc4514). K. Zeilenga. IETF. June 2006. Proposed Standard.

[RFC 4648 - The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648). S. Josefsson. IETF. October 2006. Proposed Standard.

[RFC 5234 - Augmented BNF for Syntax Specifications: ABNF](https://www.rfc-editor.org/rfc/rfc5234.html). D. Crocker, P. Overell. IETF. January 2008. Internet Standard.

[RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986). T. Berners-Lee, R. Fielding, L. Masinter. IETF. January 2005. Internet Standard.

[FIPS 180-4 - Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final). NIST. August 2015. FIPS Publication.

### Informative references

[Analysis of hybrid wallet solutions - Implementation options for combining x509 certificates with DIDs and VCs](https://github.com/WebOfTrustInfo/rwot11-the-hague/blob/master/advance-readings/hybrid_wallet_solutions_x509_DIDs_VCs.md). Carsten Stoecker (Spherity) and Christiane Wirrig (Spherity) with support of Paul Bastian (Bundesdruckerei) and Steffen Schwalm (msg Group) in the IDunion Project. 20 July 2022. RWOT11 topic paper.

[RFC 9360 - CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates](https://www.rfc-editor.org/rfc/rfc9360). J. Schaad. IETF. February 2023. Proposed Standard.

[RFC 9597 - CBOR Web Token (CWT) Claims in COSE Headers](https://www.rfc-editor.org/rfc/rfc9597). M. Jones. IETF. June 2024. Proposed Standard.

[RFC 7519 - JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519). M. Jones, J. Bradley, N. Sakimura. IETF. May 2015. Proposed Standard.

[Verifiable Credentials Data Model v1.1](https://www.w3.org/TR/2022/REC-vc-data-model-20220303/). Manu Sporny, Dave Longley, David Chadwick. W3C. 03 March 2022. W3C Recommendation.

[Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/). Open Policy Agent contributors.

[Fulcio](https://github.com/sigstore/fulcio). Fulcio contributors.
