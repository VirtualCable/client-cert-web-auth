FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV SMARTCARD_AUTH_CONFIG=/app/config/config.yaml
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    python3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh

RUN /usr/local/bin/uv python install 3.12

WORKDIR /app

COPY pyproject.toml ./
RUN /usr/local/bin/uv sync

COPY app/ ./app/
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY nginx/default.conf /etc/nginx/sites-available/default
COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh

RUN rm -f /etc/nginx/sites-enabled/default && \
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && \
    mkdir -p /run/nginx && \
    chmod +x /docker-entrypoint.sh

EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
