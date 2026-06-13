#!/usr/bin/env python3
import secrets
import sys
import yaml

CONFIG_TEMPLATE = {
    "hmac_key": secrets.token_hex(32),
    "uds_callback_url": "https://uds.example.com/uds/page/auth/callback/smartcard/",
    "listen_host": "127.0.0.1",
    "listen_port": 8080,
}


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"

    with open(output_path, "w") as f:
        yaml.dump(CONFIG_TEMPLATE, f, default_flow_style=False, sort_keys=False)

    print(f"Config written to {output_path}")
    print(f"HMAC key: {CONFIG_TEMPLATE['hmac_key']}")


if __name__ == "__main__":
    main()
