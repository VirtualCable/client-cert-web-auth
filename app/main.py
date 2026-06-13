from __future__ import annotations

import asyncio
import logging

from aiohttp import web

from app.config import AppConfig, load_config
from app.handler import handle_cert_auth, handle_health

logger = logging.getLogger(__name__)


def create_app(config: AppConfig) -> web.Application:
    app = web.Application()
    app["config"] = config

    app.router.add_get("/cert_auth/", handle_cert_auth)
    app.router.add_get("/cert_auth/{path_param:.+}", handle_cert_auth)
    app.router.add_get("/health", handle_health)

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    config = load_config()

    async def _run() -> None:
        app = create_app(config)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, config.listen_host, config.listen_port)
        await site.start()
        logger.info("Serving on %s:%s", config.listen_host, config.listen_port)
        await asyncio.Event().wait()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
