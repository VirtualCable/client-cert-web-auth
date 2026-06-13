# UDS Smartcard Auth — Client Certificate Bridge

Lightweight Docker service that acts as a bridge between a TLS client-certificate
protected endpoint and the UDS authentication system.

When a user accesses this service with a client certificate, the certificate
data is encrypted and forwarded to the UDS server for authentication.

## How it works

```
Browser ──TLS + client cert──▶ nginx (:443) ──proxy_pass──▶ aiohttp (:8080)
                                      │                          │
                                      │                encrypts cert
                                      │                returns auto-submit form
                                      ▼                          │
                              X-Client-Cert header    POST to UDS callback ▼
                                                       UDS auth_callback
```

1. UDS generates a signed link pointing to this service with the callback and
   return URLs embedded in the path.
2. The browser performs a TLS handshake with its client certificate.
3. Nginx extracts the certificate and forwards it via headers to the Python app.
4. The app encrypts the certificate (AES-256-CBC + HMAC-SHA256) and returns an
   auto-submitting HTML form that POSTs the encrypted payload to UDS.
5. UDS decrypts, verifies the signature, and authenticates the user.

## Configuration

The only required configuration is a shared HMAC key, stored in `config.yaml`:

```yaml
hmac_key: "your-64-char-hex-string"
```

Generate one with:

```bash
docker run --rm \
  -v $(pwd)/config:/app/config \
  --entrypoint /usr/local/bin/uv \
  smartcard-auth run python scripts/generate_config.py
```

## Build

```bash
./build.sh
```

## Run

```bash
docker run -d --name smartcard-auth -p 443:443 \
  --log-opt max-size=10m --log-opt max-file=3 \
  -v $(pwd)/config/config.yaml:/app/config/config.yaml:ro \
  -v $(pwd)/certs:/etc/certs:ro \
  smartcard-auth
```

## Optional mounts

All of these are auto-generated on startup if not provided:

| Mount | Purpose | Auto-generated? |
|-------|---------|-----------------|
| `/etc/certs/server.pem` | Server TLS certificate | Yes (self-signed) |
| `/etc/certs/key.pem` | Server private key | Yes |
| `/etc/certs/dhparam.pem` | DH parameters | Yes (2048-bit) |
| `/etc/nginx/snippets/ssl-params.conf` | Custom SSL configuration | Falls back to built-in default |

## Environment variables (set by entrypoint)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMARTCARD_AUTH_LISTEN_HOST` | `127.0.0.1` | Internal listen address for the Python app |
| `SMARTCARD_AUTH_LISTEN_PORT` | `8080` | Internal listen port |
| `SMARTCARD_AUTH_CONFIG` | `config/config.yaml` | Path to configuration file |

## Viewing logs

```bash
docker logs -f smartcard-auth
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
