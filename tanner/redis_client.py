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
            host = TannerConfig.get('REDIS', 'host')
            port = TannerConfig.get('REDIS', 'port')
            expiry_time = TannerConfig.get('REDIS', 'expiry_time')
            if poolsize is None:
                poolsize = TannerConfig.get('REDIS', 'poolsize')
            timeout = TannerConfig.get('REDIS', 'timeout')
            redis_client = await asyncio.wait_for(aioredis.create_redis_pool(
                (host, int(port)), maxsize=int(poolsize)), timeout=int(timeout), parser=expiry_time)
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception('Problem with redis connection. Please, check your redis server. %s', timeout_error)
            exit()
        return redis_client
