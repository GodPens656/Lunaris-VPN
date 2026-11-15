"""A QUIC v1 Initial probe and authenticated reply validation (RFC 9001)."""
from __future__ import annotations

import hashlib
import hmac
import ssl

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def _expand(secret: bytes, label: bytes, size: int) -> bytes:
    label = b"tls13 " + label
    info = size.to_bytes(2) + bytes([len(label)]) + label + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=size, info=info).derive(secret)


def _keys(destination: bytes, side: bytes) -> tuple[bytes, bytes, bytes]:
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial = hmac.digest(salt, destination, hashlib.sha256)
    secret = _expand(initial, side + b" in", 32)
    return (_expand(secret, b"quic key", 16), _expand(secret, b"quic iv", 12),
            _expand(secret, b"quic hp", 16))


def _mask(key: bytes, sample: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(sample)


def _varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    return (value | 0x4000).to_bytes(2)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    size = 1 << (data[offset] >> 6)
    end = offset + size
    if end > len(data):
        raise ValueError("Truncated QUIC varint")
    return int.from_bytes(data[offset:end]) & ((1 << (size * 8 - 2)) - 1), end


def _client_hello(source: bytes) -> bytes:
    # OpenSSL constructs the TLS 1.3 ClientHello; add QUIC's mandatory
    # initial_source_connection_id transport parameter before encrypting it.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    context.set_alpn_protocols(["h3"])
    outgoing = ssl.MemoryBIO()
    client = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname="localhost")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    record = outgoing.read()
    hello = record[9:5 + int.from_bytes(record[3:5])]
    offset = 35 + hello[34]  # legacy version, random, legacy session ID
    offset += 2 + int.from_bytes(hello[offset:offset + 2])  # cipher suites
    offset += 1 + hello[offset]  # compression methods
    parameters = b"\x0f" + bytes([len(source)]) + source
    extension = b"\x00\x39" + len(parameters).to_bytes(2) + parameters
    extensions = hello[offset + 2:] + extension
    hello = hello[:offset] + len(extensions).to_bytes(2) + extensions
    return b"\x01" + len(hello).to_bytes(3) + hello


def initial_probe(destination: bytes, source: bytes) -> bytes:
    hello = _client_hello(source)
    frames = b"\x06\x00" + _varint(len(hello)) + hello
    # Four-byte packet number 0; pad the whole datagram to 1200 bytes.
    prefix = b"\xc3\x00\x00\x00\x01" + bytes([len(destination)]) + destination
    prefix += bytes([len(source)]) + source + b"\x00"  # empty token
    payload_size = 1200 - len(prefix) - 2 - 4 - 16
    frames = frames.ljust(payload_size, b"\x00")
    header = bytearray(prefix + _varint(4 + len(frames) + 16) + b"\x00" * 4)
    key, iv, hp = _keys(destination, b"client")
    encrypted = AESGCM(key).encrypt(iv, frames, bytes(header))
    mask = _mask(hp, encrypted[:16])
    header[0] ^= mask[0] & 0x0f
    for index in range(4):
        header[-4 + index] ^= mask[1 + index]
    return bytes(header) + encrypted


def is_probe_reply(data: bytes, destination: bytes, source: bytes) -> bool:
    try:
        if len(data) < 7 or data[0] & 0xc0 != 0xc0 or data[1:5] != b"\x00\x00\x00\x01":
            return False
        length = data[5]
        if data[6:6 + length] != source:
            return False
        offset = 6 + length
        length = data[offset]
        if length > 20:
            return False
        offset += 1 + length
        if data[0] & 0x30 == 0x30:  # Retry integrity tag, RFC 9001 section 5.8
            pseudo = bytes([len(destination)]) + destination + data[:-16]
            AESGCM(bytes.fromhex("be0c690b9f66575a1d766b54e368c84e")).decrypt(
                bytes.fromhex("461599d35d632bf2239825bb"), data[-16:], pseudo)
            return len(data) > offset + 16
        if data[0] & 0x30:
            return False
        token_length, offset = _read_varint(data, offset)
        offset += token_length
        packet_length, offset = _read_varint(data, offset)
        end = offset + packet_length
        if end > len(data) or packet_length < 20:
            return False
        key, iv, hp = _keys(destination, b"server")
        mask = _mask(hp, data[offset + 4:offset + 20])
        first = data[0] ^ (mask[0] & 0x0f)
        if first & 0x0c:  # Reserved bits must be zero.
            return False
        pn_size = (first & 3) + 1
        number = bytes(data[offset + index] ^ mask[1 + index] for index in range(pn_size))
        header = bytes([first]) + data[1:offset] + number
        nonce = (int.from_bytes(iv) ^ int.from_bytes(number)).to_bytes(12)
        payload = AESGCM(key).decrypt(nonce, data[offset + pn_size:end], header)
        return bool(payload)
    except (IndexError, ValueError, InvalidTag):
        return False
