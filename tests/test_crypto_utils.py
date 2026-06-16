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
# OR TORT (INCLUDING NEGLIKKHOOD OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Tests for crypto_utils module — encryption, decryption, HMAC signing."""

from __future__ import annotations

import base64
import json

import pytest

from app.crypto_utils import (
    decrypt_payload,
    encrypt_payload,
    hmac_sign,
    hmac_verify,
)

SHARED_SECRET = "test-shared-secret-key-1234567890"
OTHER_SECRET = "another-different-secret-key-abc"


class TestEncryptDecrypt:
    """Encrypt-then-MAC payload roundtrip and integrity checks."""

    def test_roundtrip_simple(self) -> None:
        """A simple string survives encrypt → decrypt with the same key."""
        plain = "hello-world"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        assert encrypted != plain  # must be obfuscated
        decrypted = decrypt_payload(encrypted, SHARED_SECRET)
        assert decrypted == plain

    def test_roundtrip_json(self) -> None:
        """JSON-encoded data roundtrips correctly."""
        payload = json.dumps(
            {
                "cert": "-----BEGIN CERTIFICATE-----\nMIIB...",
                "host": "example.com",
                "remote_ip": "192.168.1.1",
                "forwarded_for": "10.0.0.1",
                "ticket": "ticket-001",
            }
        )
        encrypted = encrypt_payload(payload, SHARED_SECRET)
        decrypted = decrypt_payload(encrypted, SHARED_SECRET)
        assert json.loads(decrypted) == json.loads(payload)

    def test_roundtrip_empty_cert(self) -> None:
        """The EMPTY sentinel value roundtrips correctly."""
        plain = "EMPTY"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        assert decrypt_payload(encrypted, SHARED_SECRET) == plain

    def test_different_secret_fails(self) -> None:
        """Decrypting with a different secret raises ValueError."""
        plain = "sensitive-data"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_payload(encrypted, OTHER_SECRET)

    def test_tampered_ciphertext_fails(self) -> None:
        """Tweaking any byte in the ciphertext causes HMAC to fail."""
        plain = "data-to-protect"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        raw = bytearray(base64.b64decode(encrypted))
        # Flip a bit in the ciphertext portion (after IV, before MAC)
        if len(raw) > 48:  # 16 (IV) + at least 1 byte ciphertext + 32 (MAC)
            raw[20] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_payload(tampered, SHARED_SECRET)

    def test_tampered_iv_fails(self) -> None:
        """Tweaking the IV causes HMAC to fail."""
        plain = "data-to-protect"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        raw = bytearray(base64.b64decode(encrypted))
        # Flip a bit in the IV (first 16 bytes)
        raw[4] ^= 0xAA
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_payload(tampered, SHARED_SECRET)

    def test_tampered_mac_fails(self) -> None:
        """Tweaking the MAC itself causes HMAC to fail."""
        plain = "data-to-protect"
        encrypted = encrypt_payload(plain, SHARED_SECRET)
        raw = bytearray(base64.b64decode(encrypted))
        # Flip a bit in the MAC (last 32 bytes)
        raw[-5] ^= 0xBB
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_payload(tampered, SHARED_SECRET)

    def test_invalid_base64_fails(self) -> None:
        """Non-base64 input raises an exception."""
        with pytest.raises(Exception):
            decrypt_payload("not-valid-base64!!!", SHARED_SECRET)

    def test_too_short_payload_fails(self) -> None:
        """Payload shorter than IV+MAC (48 bytes) raises an exception."""
        short_b64 = base64.b64encode(b"too-short").decode()
        with pytest.raises(Exception):
            decrypt_payload(short_b64, SHARED_SECRET)

    def test_deterministic_iv(self) -> None:
        """Each encryption produces a different ciphertext (random IV)."""
        plain = "same-text"
        r1 = encrypt_payload(plain, SHARED_SECRET)
        r2 = encrypt_payload(plain, SHARED_SECRET)
        assert r1 != r2

    def test_long_text(self) -> None:
        """Long plaintexts (e.g. full PEM certs) roundtrip correctly."""
        large = "A" * 10_000
        encrypted = encrypt_payload(large, SHARED_SECRET)
        assert decrypt_payload(encrypted, SHARED_SECRET) == large


class TestHMAC:
    """HMAC sign / verify operations."""

    def test_sign_verify(self) -> None:
        """Sign then verify with the same key succeeds."""
        data = "hello"
        sig = hmac_sign(data, SHARED_SECRET)
        assert hmac_verify(data, sig, SHARED_SECRET) is True

    def test_verify_wrong_key(self) -> None:
        """Verify with a different key returns False."""
        data = "hello"
        sig = hmac_sign(data, SHARED_SECRET)
        assert hmac_verify(data, sig, OTHER_SECRET) is False

    def test_verify_tampered_data(self) -> None:
        """Verify with tampered data returns False."""
        data = "hello"
        sig = hmac_sign(data, SHARED_SECRET)
        assert hmac_verify("hell0", sig, SHARED_SECRET) is False

    def test_verify_tampered_sig(self) -> None:
        """Verify with a tampered signature returns False."""
        data = "hello"
        sig = hmac_sign(data, SHARED_SECRET)
        # Flip a character in the hex digest
        tampered_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
        assert hmac_verify(data, tampered_sig, SHARED_SECRET) is False

    def test_sign_empty(self) -> None:
        """Empty string can be signed and verified."""
        sig = hmac_sign("", SHARED_SECRET)
        assert hmac_verify("", sig, SHARED_SECRET) is True

    def test_sign_unicode(self) -> None:
        """Unicode data is handled correctly."""
        data = "ca fé ☕"
        sig = hmac_sign(data, SHARED_SECRET)
        assert hmac_verify(data, sig, SHARED_SECRET) is True

    def test_sign_json_blob(self) -> None:
        """JSON blobs (like those used in signed URLs) work correctly."""
        data = '{"url":"https://example.com/callback","ticket":"abc-123"}'
        sig = hmac_sign(data, SHARED_SECRET)
        assert hmac_verify(data, sig, SHARED_SECRET) is True
