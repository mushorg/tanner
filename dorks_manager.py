import pickle
import re
import random
import os
import asyncio
import asyncio_redis
import uuid
import patterns


class DorksManager:
    dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'dorks').hex
    user_dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'user_dorks').hex

    if os.path.exists('user_dorks.pickle'):
        with open('user_dorks.pickle', 'rb') as ud:
            user_dorks = pickle.load(ud)

    def __init__(self, redis_client):
        self.redis = redis_client
        # if not (yield from self.redis.exists(self.dorks_key)):
        #  self.push_init_dorks('dorks.pickle', self.dorks_key)
        #   if not (yield from self.redis.exists(self.user_dorks_key)):
        # self.push_init_dorks('user_dorks.pickle', self.user_dorks_key)

    @asyncio.coroutine
    def push_init_dorks(self, file_name, redis_key):
        dorks = None
        if os.path.exists(file_name):
            with open(file_name, 'rb') as ud:
                dorks = pickle.load(ud)
        if dorks:
            if type(dorks) is str:
                dorks = dorks.split()
            yield from self.redis.sadd(redis_key, *dorks)

    @asyncio.coroutine
    def extract_path(self, path):
        extracted = re.match(patterns.QUERY, path)
        if extracted:
            extracted = extracted.group(0)
            if not self.user_dorks_key:
                self.user_dorks_key = uuid.uuid4().hex

            extracted = extracted.split()
            yield from self.redis.sadd(self.user_dorks_key, *extracted)

    @asyncio.coroutine
    def choose_dorks(self):
        chosen_dorks = []
        max_dorks = 50
        dorks = yield from self.redis.smembers(self.dorks_key)
        dorks = yield from dorks.asset()
        user_dorks = self.redis.smembers(self.user_dorks_key)
        user_dorks = yield from user_dorks.asset()
        chosen_dorks.extend(random.sample(dorks, random.randint(0.5 * max_dorks, max_dorks)))
        try:
            if max_dorks > len(user_dorks):
                max_dorks = len(user_dorks)
            chosen_dorks.extend(random.sample(user_dorks, random.randint(0.5 * max_dorks, max_dorks)))
        except TypeError:
            pass
        finally:
            for i, val in enumerate(chosen_dorks):
                chosen_dorks[i] = val.decode('utf-8')
            return chosen_dorks
