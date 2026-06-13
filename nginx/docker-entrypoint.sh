#!/bin/bash
set -e

echo "Starting nginx..."
nginx -c /etc/nginx/nginx.conf

echo "Starting smartcard-auth app..."
exec uv run python -m app.main
