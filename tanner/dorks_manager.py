import logging
import math
import os
import pickle
import random
import re
import uuid

import aioredis

from tanner import config
from tanner.utils import patterns


class DorksManager:
    dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, "dorks").hex
    user_dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, "user_dorks").hex

    def __init__(self):
        self.logger = logging.getLogger("tanner.dorks_manager.DorksManager")
        self.init_done = False

    @staticmethod
    async def push_init_dorks(file_name, redis_key, redis_client):
        dorks = None
        if os.path.exists(file_name):
            with open(file_name, "rb") as dorks_file:
                dorks = pickle.load(dorks_file)
        if dorks:
            if isinstance(dorks, str):
                dorks = dorks.split()
            if isinstance(dorks, set):
                dorks = [x for x in dorks if x is not None]
            await redis_client.sadd(redis_key, *dorks)

    async def extract_path(self, path, redis_client):
        extracted = re.match(patterns.QUERY, path)
        if extracted:
            extracted = extracted.group(0)
            try:
                await redis_client.sadd(self.user_dorks_key, *[extracted])
            except aioredis.ConnectionError as connection_error:
                self.logger.exception("Problem with redis connection: %s", connection_error)

    async def init_dorks(self, redis_client):
        try:
            transaction = redis_client.multi()
            dorks_exist = transaction.exists(self.dorks_key)
            user_dorks_exist = transaction.exists(self.user_dorks_key)

            await transaction.execute()
        except (aioredis.RedisError, aioredis.ConnectionError) as redis_error:
            self.logger.exception("Problem with transaction: %s", redis_error)
        else:
            dorks_existed = await dorks_exist
            user_dorks_existed = await user_dorks_exist

            if not dorks_existed:
                await self.push_init_dorks(config.TannerConfig.get("DATA", "dorks"), self.dorks_key, redis_client)
            if not user_dorks_existed:
                await self.push_init_dorks(
                    config.TannerConfig.get("DATA", "user_dorks"), self.user_dorks_key, redis_client
                )

            self.init_done = True

    async def choose_dorks(self, redis_client):
        if not self.init_done:
            await self.init_dorks(redis_client)
        chosen_dorks = []
        max_dorks = 50
        try:
            transaction = redis_client.multi()
            dorks = transaction.smembers(self.dorks_key, encoding="utf-8")
            user_dorks = transaction.smembers(self.user_dorks_key, encoding="utf-8")

            await transaction.execute()
        except (aioredis.RedisError, aioredis.ConnectionError) as redis_error:
            self.logger.exception("Problem with transaction: %s", redis_error)
        else:
            dorks = await dorks
            user_dorks = await user_dorks
            chosen_dorks.extend(random.sample(dorks, random.randint(math.floor(0.5 * max_dorks), max_dorks)))
            try:
                if max_dorks > len(user_dorks):
                    max_dorks = len(user_dorks)
                chosen_dorks.extend(random.sample(user_dorks, random.randint(math.floor(0.5 * max_dorks), max_dorks)))
            except TypeError:
                pass
            return chosen_dorks
