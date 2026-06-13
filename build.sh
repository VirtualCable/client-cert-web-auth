#!/bin/bash
set -e

IMAGE="smartcard-auth"

echo "Building ${IMAGE}..."
docker build -t "${IMAGE}" .

echo ""
echo "Done. Run with:"
echo ""
echo "  docker run -p 443:443 \\"
echo "    -v \$(pwd)/config/config.yaml:/app/config/config.yaml:ro \\"
echo "    -v \$(pwd)/certs:/etc/certs:ro \\"
echo "    ${IMAGE}"
echo ""
echo "Generate a config first if needed:"
echo ""
echo "  docker run --rm \\"
echo "    -v \$(pwd)/config:/app/config \\"
echo "    --entrypoint /usr/local/bin/uv \\"
echo "    ${IMAGE} run python scripts/generate_config.py"
