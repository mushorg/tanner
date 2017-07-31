import asyncio
import logging

import asyncio_redis

from tanner.config import TannerConfig

LOGGER = logging.getLogger(__name__)


class RedisClient:
    @staticmethod
    async def get_redis_client(poolsize=None):
        redis_client = None
        try:
            host = TannerConfig.get('REDIS', 'host')
            port = TannerConfig.get('REDIS', 'port')
            if poolsize is None:
                poolsize = TannerConfig.get('REDIS', 'poolsize')
            timeout = TannerConfig.get('REDIS', 'timeout')
            redis_client = await asyncio.wait_for(asyncio_redis.Pool.create(
                host=host, port=int(port), poolsize=int(poolsize)), timeout=int(timeout))
        except asyncio.TimeoutError as timeout_error:
            LOGGER.error('Problem with redis connection. Please, check your redis server. %s', timeout_error)
            exit()
        return redis_client