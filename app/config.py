from __future__ import annotations

import os
from dataclasses import dataclass

import yaml


@dataclass(frozen=True)
class AppConfig:
    hmac_key: str
    uds_callback_url: str
    listen_host: str
    listen_port: int


def load_config(path: str | None = None) -> AppConfig:
    if path is None:
        path = os.environ.get("SMARTCARD_AUTH_CONFIG", "config/config.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)
    return AppConfig(
        hmac_key=data["hmac_key"],
        uds_callback_url=data["uds_callback_url"],
        listen_host=data.get("listen_host", "127.0.0.1"),
        listen_port=data.get("listen_port", 8080),
    )
