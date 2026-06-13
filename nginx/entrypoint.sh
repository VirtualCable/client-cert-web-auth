#!/bin/bash
set -e

CERT_DIR="/etc/certs"
CERT_FILE="${CERT_DIR}/server.pem"
KEY_FILE="${CERT_DIR}/key.pem"
DH_RUNTIME="/run/dhparam.pem"

CLIENT_CERT_AUTH_PID=""
NGINX_PID=""

# --- Generate self-signed certificates if not mounted ---
if [ ! -f "${CERT_FILE}" ] || [ ! -f "${KEY_FILE}" ]; then
    echo "[entrypoint] No SSL certificates found at ${CERT_DIR}. Generating self-signed..."
    mkdir -p "${CERT_DIR}"
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout "${KEY_FILE}" \
        -out "${CERT_FILE}" \
        -subj "/C=ES/ST=Madrid/L=Madrid/O=VirtualCable/OU=UDS/CN=localhost" \
        2>/dev/null
    echo "[entrypoint] Self-signed certificates generated."
fi

# --- Generate dhparam if not exists ---
if [ -f "${CERT_DIR}/dhparam.pem" ]; then
    echo "[entrypoint] Using mounted DH parameters from ${CERT_DIR}/dhparam.pem"
    ln -sf "${CERT_DIR}/dhparam.pem" "${DH_RUNTIME}"
elif [ -w "${CERT_DIR}" ]; then
    echo "[entrypoint] No DH parameters found. Generating (2048 bits)..."
    openssl dhparam -out "${DH_RUNTIME}" 2048 2>/dev/null
    echo "[entrypoint] DH parameters generated at ${DH_RUNTIME}"
else
    echo "[entrypoint] No DH parameters found. Generating (2048 bits)..."
    openssl dhparam -out "${DH_RUNTIME}" 2048 2>/dev/null
    echo "[entrypoint] DH parameters generated at ${DH_RUNTIME}"
fi

# --- Configure Nginx SSL Snippet ---
DEFAULT_SNIPPET="/etc/nginx/snippets-available/uds-ssl.conf"
SSL_PARAMS_PATH="/etc/nginx/snippets/ssl-params.conf"

if [ ! -f "${SSL_PARAMS_PATH}" ]; then
    echo "[entrypoint] No custom SSL params found. Using default UDS SSL profile with client certificate."
    ln -sf "${DEFAULT_SNIPPET}" "${SSL_PARAMS_PATH}"
else
    echo "[entrypoint] Using custom SSL configuration mounted at ${SSL_PARAMS_PATH}"
fi

# --- Handle graceful shutdown ---
cleanup() {
    echo "[entrypoint] Shutting down..."
    [ -n "${CLIENT_CERT_AUTH_PID}" ] && kill -TERM ${CLIENT_CERT_AUTH_PID} 2>/dev/null || true
    nginx -s quit 2>/dev/null || true
    [ -n "${CLIENT_CERT_AUTH_PID}" ] && wait ${CLIENT_CERT_AUTH_PID} 2>/dev/null || true
    echo "[entrypoint] Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

# --- Set Network Environment Variables ---
# These override values in config.yaml to ensure consistency with nginx proxy_pass
export CLIENT_CERT_AUTH_LISTEN_HOST="${CLIENT_CERT_AUTH_LISTEN_HOST:-127.0.0.1}"
export CLIENT_CERT_AUTH_LISTEN_PORT="${CLIENT_CERT_AUTH_LISTEN_PORT:-8080}"

# --- Start client-cert-auth app ---
echo "[entrypoint] Starting client-cert-auth app..."
uv run python -m app.main &
CLIENT_CERT_AUTH_PID=$!
echo "[entrypoint] Client-cert-auth app started (PID: ${CLIENT_CERT_AUTH_PID})"

# --- Start nginx in foreground ---
echo "[entrypoint] Starting nginx..."
nginx -g 'daemon off;' &
NGINX_PID=$!

# --- Monitor processes ---
while true; do
    if [ -n "${CLIENT_CERT_AUTH_PID}" ]; then
        if ! kill -0 ${CLIENT_CERT_AUTH_PID} 2>/dev/null; then
            echo "[entrypoint] Client-cert-auth app exited unexpectedly."
            cleanup
        fi
    fi
    if ! kill -0 ${NGINX_PID} 2>/dev/null; then
        echo "[entrypoint] Nginx exited unexpectedly."
        cleanup
    fi
    sleep 5
done
