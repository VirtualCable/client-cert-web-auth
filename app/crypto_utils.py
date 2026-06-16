# -*- coding: utf-8 -*-
#
# Copyright (c) 2025-2026 Virtual Cable S.L.U.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def _derive_keys(shared_secret: str) -> tuple[bytes, bytes, bytes]:
    """Derive encryption, MAC, and signing keys from the shared secret.

    Returns (enc_key, mac_key, sign_key) — three separate derived keys
    so that a compromise of one usage (signing vs. encryption) does not
    affect the others (key separation).
    """
    secret = shared_secret.encode()
    enc_key = hashlib.sha256(secret + b"enc").digest()
    mac_key = hashlib.sha256(secret + b"mac").digest()
    sign_key = hashlib.sha256(secret + b"sign").digest()
    return enc_key, mac_key, sign_key


def encrypt_payload(plaintext: str, shared_secret: str) -> str:
    enc_key, mac_key, _ = _derive_keys(shared_secret)
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
    enc_key, mac_key, _ = _derive_keys(shared_secret)

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
    _, _, sign_key = _derive_keys(shared_secret)
    h = hmac_module.new(sign_key, data.encode(), hashlib.sha256)
    return h.hexdigest()


def hmac_verify(data: str, signature_hex: str, shared_secret: str) -> bool:
    expected = hmac_sign(data, shared_secret)
    return hmac_module.compare_digest(expected, signature_hex)
