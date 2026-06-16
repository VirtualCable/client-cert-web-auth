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
import html
import json
import logging

from aiohttp.web import Request, Response

from app.config import AppConfig
from app.crypto_utils import encrypt_payload, hmac_sign, hmac_verify

logger = logging.getLogger(__name__)

EMPTY_CERT_SENTINEL = "EMPTY"

AUTO_SUBMIT_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Client Certificate Authentication</title>
</head>
<body>
    <p>Redirecting...</p>
    <form id="f" method="POST" action="{target_url}">
        <input type="hidden" name="payload" value="{payload}">
    </form>
    <script>document.getElementById('f').submit();</script>
</body>
</html>"""


async def handle_cert_auth(request: Request) -> Response:
    config: AppConfig = request.app["config"]

    cert_pem = request.headers.get("X-Client-Cert", "")
    host = request.headers.get("Host", "")
    remote = request.remote or ""
    forwarded = request.headers.get("X-Forwarded-For", "")

    if cert_pem:
        logger.info("Client certificate received from %s", remote)
    else:
        logger.info("No client certificate from %s", remote)

    if not cert_pem:
        cert_pem = EMPTY_CERT_SENTINEL

    target_url, ticket_id = _extract_signed_data(request, config)

    data = json.dumps({
        "cert": cert_pem,
        "host": host,
        "remote_ip": remote,
        "forwarded_for": forwarded,
        "ticket": ticket_id,
    })

    encrypted_payload = encrypt_payload(data, config.hmac_key)

    logger.info("Redirecting to UDS: %s (ticket: %s)", target_url or "(none)", ticket_id or "(none)")

    body = AUTO_SUBMIT_TEMPLATE.format(
        target_url=html.escape(target_url),
        payload=html.escape(encrypted_payload),
    )

    return Response(text=body, content_type="text/html")


def _extract_signed_data(request: Request, config: AppConfig) -> tuple[str, str]:
    """Extract (url, ticket_id) from the signed path param."""
    path_param = request.match_info.get("path_param", None)
    if path_param:
        result = _decode_signed_data(path_param, config)
        if result:
            return result.get("url", ""), result.get("ticket", "")
        logger.warning("Path payload HMAC verification failed")

    return "", ""


def _decode_signed_data(encoded: str, config: AppConfig) -> dict[str, str] | None:
    """Decode base64url(json).hmac_hex back to dict with 'url' and optionally 'ticket'."""
    try:
        data_b64, sig = encoded.rsplit(".", 1)
        if not hmac_verify(data_b64, sig, config.hmac_key):
            return None

        padding = 4 - len(data_b64) % 4
        if padding != 4:
            data_b64 += "=" * padding

        decoded = base64.urlsafe_b64decode(data_b64).decode()
        return json.loads(decoded)
    except Exception:
        return None


def encode_signed_data(url: str, ticket_id: str, hmac_key: str) -> str:
    """Encode JSON {url, ticket} as base64url(json).hmac_hex."""
    payload = json.dumps({"url": url, "ticket": ticket_id}, separators=(",", ":"))
    data_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig = hmac_sign(data_b64, hmac_key)
    return f"{data_b64}.{sig}"


async def handle_catch_all(request: Request) -> Response:
    return Response(text="", content_type="text/plain")
