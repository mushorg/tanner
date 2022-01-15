import asyncio
import logging

import aioredis

from tanner.config import TannerConfig

LOGGER = logging.getLogger(__name__)


class RedisClient:
    @staticmethod
    async def get_redis_client(poolsize=None):
        redis_client = None
        try:
            host = TannerConfig.get("REDIS", "host")
            port = TannerConfig.get("REDIS", "port")
            username=""
            password=""

            if poolsize is None:
                poolsize = TannerConfig.get("REDIS", "poolsize")
            redis_client = aioredis.from_url(
                            f"redis://{username}:{password}@{host}:{port}",
                            encoding="utf-8",
                            decode_responses=True,
                            max_connections=poolsize
            )
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception("Problem with redis connection. Please, check your redis server. %s", timeout_error)
            exit()
        return redis_client
