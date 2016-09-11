import asyncio
import logging
import os
import pickle
import random
import re
import uuid

import asyncio_redis

from tanner.utils import patterns


class DorksManager:
    dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'dorks').hex
    user_dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'user_dorks').hex

    def __init__(self):
        self.logger = logging.getLogger('tanner.dorks_manager.DorksManager')
        self.init_done = False

    @staticmethod
    @asyncio.coroutine
    def push_init_dorks(file_name, redis_key, redis_client):
        dorks = None
        if os.path.exists(file_name):
            with open(file_name, 'rb') as dorks_file:
                dorks = pickle.load(dorks_file)
        if dorks:
            if isinstance(dorks, str):
                dorks = dorks.split()
            if isinstance(dorks, set):
                dorks = [x for x in dorks if x is not None]
            yield from redis_client.sadd(redis_key, dorks)

    @asyncio.coroutine
    def extract_path(self, path, redis_client):
        extracted = re.match(patterns.QUERY, path)
        if extracted:
            extracted = extracted.group(0)
            
            try:
            	yield from redis_client.sadd(self.user_dorks_key, [extracted])
            except asyncio_redis.NotConnectedError as connection_error:
                self.logger('Problem with redis connection: %s', connection_error)

    @asyncio.coroutine
    def init_dorks(self, redis_client):
        try:
            transaction = yield from redis_client.multi()
            dorks_exist = yield from transaction.exists(self.dorks_key)
            user_dorks_exist = yield from transaction.exists(self.user_dorks_key)

            yield from transaction.exec()
        except (asyncio_redis.TransactionError, asyncio_redis.NotConnectedError) as redis_error:
            self.logger('Problem with transaction: %s', redis_error)
        else:
            dorks_existed = yield from dorks_exist
            user_dorks_existed = yield from user_dorks_exist

            if not dorks_existed:
                yield from self.push_init_dorks('dorks.pickle', self.dorks_key, redis_client)
            if not user_dorks_existed:
                yield from self.push_init_dorks('user_dorks.pickle', self.user_dorks_key, redis_client)

            self.init_done = True

    @asyncio.coroutine
    def choose_dorks(self, redis_client):
        if not self.init_done:
            yield from self.init_dorks(redis_client)
        chosen_dorks = []
        max_dorks = 50
        try:
            transaction = yield from redis_client.multi()
            dorks = yield from transaction.smembers_asset(self.dorks_key)
            user_dorks = yield from transaction.smembers_asset(self.user_dorks_key)

            yield from transaction.exec()
        except (asyncio_redis.TransactionError, asyncio_redis.NotConnectedError) as redis_error:
            self.logger('Problem with transaction: %s', redis_error)
        else:
            dorks = yield from dorks
            user_dorks = yield from user_dorks
            chosen_dorks.extend(random.sample(dorks, random.randint(0.5 * max_dorks, max_dorks)))
            try:
                if max_dorks > len(user_dorks):
                    max_dorks = len(user_dorks)
                chosen_dorks.extend(random.sample(
                    user_dorks, random.randint(0.5 * max_dorks, max_dorks)))
            except TypeError:
                pass
            return chosen_dorks
