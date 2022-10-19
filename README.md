# did:x509

This repository contains the DRAFT specification of the did:x509 [DID](https://www.w3.org/TR/did-core/) method. It aims to achieve interoperability between existing X.509 solutions and Decentralized Identifiers (DIDs) to support operational models in which a full transition to DIDs is not achievable or desired yet.

NOTE: This specification is in its early development and is published to invite feedback from the community. Please contribute by opening issues and pull requests!

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
python did_x509.py resolve did:x509:0:sha256:hH32p4SXlD8n_HLrk_mmNzIKArVh0KkbCeh6eAftfGE::subject:CN:Microsoft%20Corporation --chain test-data/ms-code-signing.pem
# Output: { <DID document> }
```

To convert a certificate chain to the JSON data model defined in the specification, run:

```sh
python did_x509.py convert test-data/ms-code-signing.pem
# Output: [ Certificate chain in JSON ]
```

To percent-encode a string for use in policies, run:

```sh
python did_x509.py encode "My Org"
# Output: My%20Org
```

Run tests with:

```
pytest -v test.py
```

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).

### Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
