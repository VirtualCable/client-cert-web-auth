from __future__ import annotations

import base64
import html

from aiohttp import web
from aiohttp.web import Request, Response

from app.config import AppConfig
from app.crypto_utils import encrypt_payload, hmac_verify

EMPTY_CERT_SENTINEL = "EMPTY"

AUTO_SUBMIT_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Smartcard Authentication</title>
</head>
<body>
    <p>Redirecting...</p>
    <form id="f" method="POST" action="{callback_url}">
        <input type="hidden" name="payload" value="{payload}">
        <input type="hidden" name="host" value="{host}">
        <input type="hidden" name="return_url" value="{return_url}">
    </form>
    <script>document.getElementById('f').submit();</script>
</body>
</html>"""


async def handle_cert_auth(request: Request) -> Response:
    config: AppConfig = request.app["config"]

    cert_pem = request.headers.get("X-Client-Cert", "")
    host = request.headers.get("Host", "")

    if not cert_pem:
        cert_pem = EMPTY_CERT_SENTINEL

    encrypted_payload = encrypt_payload(cert_pem, config.hmac_key)
    return_url = _extract_return_url(request, config)

    body = AUTO_SUBMIT_TEMPLATE.format(
        callback_url=html.escape(config.uds_callback_url),
        payload=html.escape(encrypted_payload),
        host=html.escape(host),
        return_url=html.escape(return_url or ""),
    )

    return Response(text=body, content_type="text/html")


def _extract_return_url(request: Request, config: AppConfig) -> str | None:
    path_param = request.match_info.get("path_param", None)
    if path_param:
        url = _decode_return_url(path_param, config)
        if url:
            return url

    return_url_b64 = request.query.get("return_url")
    sig = request.query.get("sig")

    if return_url_b64 and sig and hmac_verify(return_url_b64, sig, config.hmac_key):
        try:
            return base64.urlsafe_b64decode(return_url_b64).decode()
        except Exception:
            return None

    return None


def _decode_return_url(encoded: str, config: AppConfig) -> str | None:
    try:
        parts = encoded.rsplit(".", 1)
        if len(parts) != 2:
            return None

        data_b64, sig = parts
        if not hmac_verify(data_b64, sig, config.hmac_key):
            return None

        padding = 4 - len(data_b64) % 4
        if padding != 4:
            data_b64 += "=" * padding

        return base64.urlsafe_b64decode(data_b64).decode()
    except Exception:
        return None


async def handle_health(request: Request) -> Response:
    return Response(text="OK")
