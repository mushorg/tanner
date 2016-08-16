import pickle
import re
import random
import os
import asyncio
import asyncio_redis
import logging
import uuid
import patterns


class DorksManager:
    dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'dorks').hex
    user_dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'user_dorks').hex

    def __init__(self):
        self.logger = logging.getLogger('tanner.dorks_manager.DorksManager')
        self.init_done = False

    @asyncio.coroutine
    def push_init_dorks(self, file_name, redis_key, redis_client):
        dorks = None
        if os.path.exists(file_name):
            with open(file_name, 'rb') as ud:
                dorks = pickle.load(ud)
            ud.close()
        if dorks:
            if type(dorks) is str:
                dorks = dorks.split()
            yield from redis_client.sadd(redis_key, *dorks)

    @asyncio.coroutine
    def extract_path(self, path, redis_client):
        extracted = re.match(patterns.QUERY, path)
        if extracted:
            extracted = extracted.group(0)
            if not self.user_dorks_key:
                self.user_dorks_key = uuid.uuid4().hex

            extracted = extracted.split()
            yield from redis_client.sadd(self.user_dorks_key, *extracted)

    @asyncio.coroutine
    def init_dorks(self, redis_client):
        transaction = yield from redis_client.multi()
        dorks_exist = yield from transaction.exists(self.dorks_key)
        user_dorks_exist = yield from transaction.exists(self.user_dorks_key)

        yield from transaction.exec()
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
        transaction = yield from redis_client.multi()
        dorks_set = yield from transaction.smembers(self.dorks_key)
        user_dorks_set = yield from transaction.smembers(self.user_dorks_key)

        yield from transaction.exec()

        dorks = yield from (yield from dorks_set).asset()
        user_dorks = yield from (yield from user_dorks_set).asset()

        chosen_dorks.extend(random.sample(dorks, random.randint(0.5 * max_dorks, max_dorks)))
        try:
            if max_dorks > len(user_dorks):
                max_dorks = len(user_dorks)
            chosen_dorks.extend(random.sample(user_dorks, random.randint(0.5 * max_dorks, max_dorks)))
        except TypeError:
            pass
        finally:
            return chosen_dorks
