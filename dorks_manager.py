import pickle
import re
import random
import os
import redis
import uuid


class DorksManager:
    dorks_key = None
    user_dorks_key = None

    if os.path.exists('user_dorks.pickle'):
        with open('user_dorks.pickle', 'rb') as ud:
            user_dorks = pickle.load(ud)

    def __init__(self):
        self.r = redis.StrictRedis(host='localhost', port=6379)
        if self.dorks_key is None:
            self.dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'dorks').hex
            self.push_init_dorks('dorks.pickle', self.dorks_key)
        if self.user_dorks_key is None:
            self.user_dorks_key = uuid.uuid3(uuid.NAMESPACE_DNS, 'user_dorks').hex
            self.push_init_dorks('user_dorks.pickle', self.user_dorks_key)

    def push_init_dorks(self, file_name, redis_key):
        dorks = None
        if os.path.exists(file_name):
            with open(file_name, 'rb') as ud:
                dorks = pickle.load(ud)
        if dorks:
            if type(dorks) is str:
                dorks = dorks.split()
            self.r.sadd(redis_key, *dorks)

    def extract_path(self, path):
        extracted = re.match(r'(.*\?)=', path)
        if extracted:
            extracted = extracted.group(0)
            print("extracted %s" % extracted)
            if not self.user_dorks_key:
                self.user_dorks_key = uuid.uuid4().hex

            extracted = extracted.split()
            self.r.sadd(self.user_dorks_key, *extracted)

    def choose_dorks(self):
        chosen_dorks = []
        max_dorks = 50
        dorks = self.r.smembers(self.dorks_key)
        user_dorks = self.r.smembers(self.user_dorks_key)
        chosen_dorks.extend(random.sample(dorks, random.randint(0.5 * max_dorks, max_dorks)))
        try:
            if max_dorks > len(user_dorks):
                max_dorks = len(user_dorks)
            chosen_dorks.extend(random.sample(user_dorks, random.randint(0.5 * max_dorks, max_dorks)))
        except TypeError:
            pass
        finally:
            return chosen_dorks
