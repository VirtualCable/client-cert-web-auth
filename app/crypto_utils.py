from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def _derive_keys(shared_secret: str) -> tuple[bytes, bytes]:
    secret = shared_secret.encode()
    enc_key = hashlib.sha256(secret + b"enc").digest()
    mac_key = hashlib.sha256(secret + b"mac").digest()
    return enc_key, mac_key


def encrypt_payload(plaintext: str, shared_secret: str) -> str:
    enc_key, mac_key = _derive_keys(shared_secret)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac_module.new(mac_key, iv + ciphertext, hashlib.sha256)
    mac = h.digest()

    return base64.b64encode(iv + ciphertext + mac).decode()


def decrypt_payload(payload_b64: str, shared_secret: str) -> str:
    enc_key, mac_key = _derive_keys(shared_secret)

    raw = base64.b64decode(payload_b64)
    iv = raw[:16]
    mac = raw[-32:]
    ciphertext = raw[16:-32]

    expected_mac = hmac_module.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac_module.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed")

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode()


def hmac_sign(data: str, shared_secret: str) -> str:
    mac_key = _derive_keys(shared_secret)[1]
    h = hmac_module.new(mac_key, data.encode(), hashlib.sha256)
    return h.hexdigest()


def hmac_verify(data: str, signature_hex: str, shared_secret: str) -> bool:
    expected = hmac_sign(data, shared_secret)
    return hmac_module.compare_digest(expected, signature_hex)
