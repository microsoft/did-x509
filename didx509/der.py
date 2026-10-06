# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


def decode_der_utf8_string(value: bytes) -> str:
    """Decode exactly one complete primitive universal DER UTF8String."""
    if not value or value[0] != 0x0C:
        raise ValueError("Value is not a primitive DER UTF8String.")
    if len(value) < 2:
        raise ValueError("DER UTF8String length is truncated.")

    length = value[1]
    offset = 2
    if length == 0x80:
        raise ValueError("DER UTF8String length is not definite.")
    if length == 0xFF:
        raise ValueError("DER UTF8String length is invalid.")
    if length > 0x80:
        octets = length & 0x7F
        offset += octets
        if len(value) < offset:
            raise ValueError("DER UTF8String length is truncated.")
        length_bytes = value[2:offset]
        length = int.from_bytes(length_bytes, "big")
        if length_bytes[0] == 0 or length < 128:
            raise ValueError("DER UTF8String length is not minimal.")

    if len(value) != offset + length:
        raise ValueError("DER UTF8String must contain exactly one complete value.")
    try:
        return value[offset:].decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("DER UTF8String is not valid UTF-8.") from e
