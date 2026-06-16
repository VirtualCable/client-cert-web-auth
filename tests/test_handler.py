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

"""Tests for handler module — signed URL encoding/decoding and HTTP handlers."""

from __future__ import annotations

import base64
import json
import re

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from app.config import AppConfig
from app.crypto_utils import decrypt_payload, hmac_sign
from app.handler import (
    _decode_signed_data,
    _extract_signed_data,
    encode_signed_data,
    handle_cert_auth,
    handle_catch_all,
)

TEST_HMAC_KEY = "test-hmac-key-32bytes-long!!!"


# ---------------------------------------------------------------------------
# Unit tests: signed data encode / decode
# ---------------------------------------------------------------------------


class TestEncodeDecodeSignedData:
    """encode_signed_data / _decode_signed_data roundtrip and edge cases."""

    def test_roundtrip(self) -> None:
        """Encoding then decoding returns the original data."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        encoded = encode_signed_data(
            "https://uds.example.com/callback", "ticket-001", TEST_HMAC_KEY
        )
        result = _decode_signed_data(encoded, config)
        assert result == {
            "url": "https://uds.example.com/callback",
            "ticket": "ticket-001",
        }

    def test_roundtrip_no_ticket(self) -> None:
        """Data without a ticket field still decodes correctly."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        # Manually encode data that only has 'url'
        payload = json.dumps({"url": "https://example.com/cb"}, separators=(",", ":"))
        data_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        sig = hmac_sign(data_b64, TEST_HMAC_KEY)
        encoded = f"{data_b64}.{sig}"
        result = _decode_signed_data(encoded, config)
        assert result == {"url": "https://example.com/cb"}

    def test_tampered_signature(self) -> None:
        """Tampered signature causes _decode_signed_data to return None."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        encoded = encode_signed_data("https://example.com/cb", "ticket-X", TEST_HMAC_KEY)
        # Corrupt the signature part
        parts = encoded.rsplit(".", 1)
        tampered = parts[0] + ".deadbeef" + parts[1][8:]
        assert _decode_signed_data(tampered, config) is None

    def test_tampered_payload(self) -> None:
        """Tampered base64 payload causes _decode_signed_data to return None."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        encoded = encode_signed_data("https://example.com/cb", "ticket-X", TEST_HMAC_KEY)
        parts = encoded.rsplit(".", 1)
        # Flip a char in the payload portion
        tampered_payload = ("A" if parts[0][0] != "A" else "B") + parts[0][1:]
        tampered = f"{tampered_payload}.{parts[1]}"
        assert _decode_signed_data(tampered, config) is None

    def test_wrong_key(self) -> None:
        """Decoding with the wrong HMAC key returns None."""
        config = AppConfig(
            hmac_key="different-key-here-123456", listen_host="", listen_port=0
        )
        encoded = encode_signed_data("https://example.com/cb", "ticket-X", TEST_HMAC_KEY)
        assert _decode_signed_data(encoded, config) is None

    def test_malformed_no_dot(self) -> None:
        """No dot separator causes _decode_signed_data to return None."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        assert _decode_signed_data("just-a-string-with-no-dot", config) is None

    def test_malformed_not_json(self) -> None:
        """Non-JSON payload returns None."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        data_b64 = base64.urlsafe_b64encode(b"not-json").decode().rstrip("=")
        sig = hmac_sign(data_b64, TEST_HMAC_KEY)
        encoded = f"{data_b64}.{sig}"
        assert _decode_signed_data(encoded, config) is None

    def test_encode_no_ticket(self) -> None:
        """encode_signed_data works with an empty ticket."""
        encoded = encode_signed_data("https://example.com/cb", "", TEST_HMAC_KEY)
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        result = _decode_signed_data(encoded, config)
        assert result == {"url": "https://example.com/cb", "ticket": ""}


# ---------------------------------------------------------------------------
# Unit tests: _extract_signed_data (uses make_mocked_request)
# ---------------------------------------------------------------------------


class TestExtractSignedData:
    """_extract_signed_data unit tests with mocked requests."""

    def test_returns_tuple(self) -> None:
        """Returns (url, ticket_id) from a valid signed path."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        encoded = encode_signed_data(
            "https://uds.example.com/auth", "ticket-999", TEST_HMAC_KEY
        )
        request = _mocked_cert_request(
            path_param=encoded,
            app={"config": config},
        )
        url, ticket = _extract_signed_data(request, config)
        assert url == "https://uds.example.com/auth"
        assert ticket == "ticket-999"

    def test_no_param_returns_empty(self) -> None:
        """Missing path_param returns empty strings."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        request = _mocked_cert_request(path_param=None, app={"config": config})
        url, ticket = _extract_signed_data(request, config)
        assert url == ""
        assert ticket == ""

    def test_invalid_param_returns_empty(self) -> None:
        """Invalid signed data returns empty strings."""
        config = AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="", listen_port=0)
        request = _mocked_cert_request(
            path_param="invalid-data-no-dot",
            app={"config": config},
        )
        url, ticket = _extract_signed_data(request, config)
        assert url == ""
        assert ticket == ""


# ---------------------------------------------------------------------------
# Unit tests: HTTP handler — handle_cert_auth
# ---------------------------------------------------------------------------


class TestHandleCertAuth:
    """Tests for the main cert_auth HTTP handler."""

    @pytest.fixture
    def config(self) -> AppConfig:
        return AppConfig(hmac_key=TEST_HMAC_KEY, listen_host="127.0.0.1", listen_port=8080)

    @pytest.fixture
    def app(self, config: AppConfig) -> web.Application:
        app = web.Application()
        app["config"] = config
        return app

    def _signed_path(self, url: str = "https://uds.example.com/auth", ticket: str = "ticket-001") -> str:
        return encode_signed_data(url, ticket, TEST_HMAC_KEY)

    @pytest.mark.asyncio
    async def test_valid_request_returns_200(self, app: web.Application) -> None:
        """A valid cert_auth request returns HTTP 200 with HTML."""
        signed = self._signed_path()
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={
                "X-Client-Cert": "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----",
                "Host": "example.com",
            },
        )
        resp = await handle_cert_auth(request)
        assert resp.status == 200
        assert resp.content_type == "text/html"

    @pytest.mark.asyncio
    async def test_response_contains_auto_submit_form(self, app: web.Application) -> None:
        """Response is an auto-submitting form pointing to the target URL."""
        target_url = "https://uds.example.com/auth/callback"
        signed = self._signed_path(url=target_url)
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={
                "X-Client-Cert": "some-cert-data",
                "Host": "cert.example.com",
            },
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        assert target_url in body
        assert 'method="POST"' in body
        assert 'name="payload"' in body

    @pytest.mark.asyncio
    async def test_encrypted_payload_decrypts_correctly(self, app: web.Application) -> None:
        """The payload hidden field decrypts to contain cert, host, remote_ip, ticket."""
        target_url = "https://uds.example.com/callback"
        ticket = "ticket-replay-001"
        signed = self._signed_path(url=target_url, ticket=ticket)
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={
                "X-Client-Cert": "my-test-cert-pem-data",
                "Host": "cert.example.com",
                "X-Forwarded-For": "10.0.0.1, 172.16.0.2",
            },
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        payload = _extract_payload(body)
        assert payload is not None, "No payload found in response"
        decrypted = decrypt_payload(payload, TEST_HMAC_KEY)
        data: dict[str, str] = json.loads(decrypted)
        assert data["cert"] == "my-test-cert-pem-data"
        assert data["host"] == "cert.example.com"
        assert data["forwarded_for"] == "10.0.0.1, 172.16.0.2"
        assert data["ticket"] == ticket
        # remote_ip comes from request.remote — with make_mocked_request it's None
        assert data["remote_ip"] == ""

    @pytest.mark.asyncio
    async def test_no_cert_uses_empty_sentinel(self, app: web.Application) -> None:
        """Missing X-Client-Cert results in cert='EMPTY'."""
        signed = self._signed_path()
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={"Host": "example.com"},
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        payload = _extract_payload(body)
        assert payload is not None
        data: dict[str, str] = json.loads(decrypt_payload(payload, TEST_HMAC_KEY))
        assert data["cert"] == "EMPTY"

    @pytest.mark.asyncio
    async def test_empty_cert_uses_sentinel(self, app: web.Application) -> None:
        """Empty string X-Client-Cert results in cert='EMPTY'."""
        signed = self._signed_path()
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={"X-Client-Cert": "", "Host": "example.com"},
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        payload = _extract_payload(body)
        assert payload is not None
        data: dict[str, str] = json.loads(decrypt_payload(payload, TEST_HMAC_KEY))
        assert data["cert"] == "EMPTY"

    @pytest.mark.asyncio
    async def test_invalid_signed_path_still_returns_form(self, app: web.Application) -> None:
        """An invalid (tampered) signed URL still returns a form but with empty target."""
        request = _mocked_cert_request(
            path_param="invalid.signature",
            app=app,
            headers={"Host": "example.com"},
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        assert 'action=""' in body
        assert "<form" in body

    @pytest.mark.asyncio
    async def test_ticket_integrity(self, app: web.Application) -> None:
        """The ticket from the signed URL matches the ticket in the encrypted payload."""
        ticket = "unique-ticket-12345"
        signed = self._signed_path(ticket=ticket)
        request = _mocked_cert_request(
            path_param=signed,
            app=app,
            headers={"Host": "example.com"},
        )
        resp = await handle_cert_auth(request)
        body = resp.text
        assert body is not None
        payload = _extract_payload(body)
        assert payload is not None
        data: dict[str, str] = json.loads(decrypt_payload(payload, TEST_HMAC_KEY))
        assert data["ticket"] == ticket


# ---------------------------------------------------------------------------
# Unit tests: HTTP handler — handle_catch_all
# ---------------------------------------------------------------------------


class TestHandleCatchAll:
    """Any non-cert_auth path should return empty 200."""

    @pytest.mark.asyncio
    async def test_root_returns_empty_200(self) -> None:
        request = make_mocked_request("GET", "/")
        resp = await handle_catch_all(request)
        assert resp.status == 200
        assert resp.text == ""
        assert resp.content_type == "text/plain"

    @pytest.mark.asyncio
    async def test_unknown_path_returns_empty_200(self) -> None:
        request = make_mocked_request("GET", "/some/random/path")
        resp = await handle_catch_all(request)
        assert resp.status == 200
        assert resp.text == ""

    @pytest.mark.asyncio
    async def test_post_method_returns_empty_200(self) -> None:
        request = make_mocked_request("POST", "/anything")
        resp = await handle_catch_all(request)
        assert resp.status == 200
        assert resp.text == ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mocked_cert_request(
    path_param: str | None,
    app: object = None,
    headers: dict[str, str] | None = None,
) -> web.Request:
    """Build a mocked request for the /cert_auth/{path_param} endpoint.

    Uses aiohttp's ``make_mocked_request`` — method is the first positional arg.
    """
    match_info: dict[str, str] = {}
    path = "/cert_auth/"
    if path_param is not None:
        match_info["path_param"] = path_param
        path = f"/cert_auth/{path_param}"

    if headers is None:
        headers = {"Host": "localhost"}

    return make_mocked_request(
        "GET",
        path,
        headers=headers,
        match_info=match_info,
        app=app,
    )


def _extract_payload(html_body: str) -> str | None:
    """Extract the 'payload' value from an auto-submit form."""
    m = re.search(
        r'<input\s+type="hidden"\s+name="payload"\s+value="([^"]+)"',
        html_body,
    )
    return m.group(1) if m else None
