ARG DISTRO_VERSION=bookworm
FROM debian:${DISTRO_VERSION}-slim

LABEL maintainer="Virtual Cable S.L. <dkmaster@dkmon.com>"
LABEL description="UDS Smartcard Auth — Client Certificate Bridge"

ENV DEBIAN_FRONTEND=noninteractive
ENV SMARTCARD_AUTH_CONFIG=/app/config/config.yaml
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssl \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh

RUN /usr/local/bin/uv python install 3.12

RUN mkdir -p /opt/smartcard-auth /etc/certs \
    /etc/nginx/snippets-available /etc/nginx/snippets

WORKDIR /app

COPY pyproject.toml ./
RUN /usr/local/bin/uv sync

COPY app/ ./app/
COPY scripts/ ./scripts/
COPY config/ ./config/

COPY nginx/default.conf /etc/nginx/sites-available/default
COPY nginx/uds-ssl.conf /etc/nginx/snippets-available/uds-ssl.conf

COPY nginx/entrypoint.sh /opt/smartcard-auth/entrypoint.sh
RUN chmod +x /opt/smartcard-auth/entrypoint.sh

RUN rm -f /etc/nginx/sites-enabled/default && \
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && \
    mkdir -p /run/nginx

EXPOSE 443

ENTRYPOINT ["/opt/smartcard-auth/entrypoint.sh"]
