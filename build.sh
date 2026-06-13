#!/bin/bash
set -e

IMAGE="smartcard-auth"

echo "Building ${IMAGE}..."
docker build -t "${IMAGE}" .

echo ""
echo "Done. Run with:"
echo ""
echo "  docker run -d --name smartcard-auth -p 443:443 \\"
echo "    --log-opt max-size=10m --log-opt max-file=3 \\"
echo "    -v \$(pwd)/config/config.yaml:/app/config/config.yaml:ro \\"
echo "    -v \$(pwd)/certs:/etc/certs:ro \\"
echo "    ${IMAGE}"
echo ""
echo "Optional mounts (all auto-generated if not provided):"
echo ""
echo "  -v \$(pwd)/certs/server.pem:/etc/certs/server.pem:ro"
echo "  -v \$(pwd)/certs/key.pem:/etc/certs/key.pem:ro"
echo "  -v \$(pwd)/certs/dhparam.pem:/etc/certs/dhparam.pem:ro"
echo "  -v \$(pwd)/nginx/custom-ssl.conf:/etc/nginx/snippets/ssl-params.conf:ro"
echo ""
echo "Generate a config first if needed:"
echo ""
echo "  docker run --rm \\"
echo "    -v \$(pwd)/config:/app/config \\"
echo "    --entrypoint /usr/local/bin/uv \\"
echo "    ${IMAGE} run python scripts/generate_config.py"
