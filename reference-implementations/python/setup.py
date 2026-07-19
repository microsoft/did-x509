from setuptools import find_packages, setup

setup(
    name="didx509",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "jwcrypto",
        "pytest",
    ],
    description="DID x509 tools",
    url="https://github.com/microsoft/did-x509",
    license="MIT",
)
