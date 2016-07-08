import asyncio
import redis
import json
import uuid
import os


class Api:
    def __init__(self):
        self.r = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)

    @asyncio.coroutine
    def handle_api_request(self, path):
        result = None

        if path[-1] == '/':
            path = path[:-1]

        request, arg = os.path.split(path)

        if request == '/api' and arg == 'stats':
            result = yield from self.return_stats()
        if request == '/api/stats':
            result = yield from self.return_uuid_stats(uuid)
        return result

    @asyncio.coroutine
    def return_stats(self):
        query_res = self.r.smembers(uuid.uuid3(uuid.NAMESPACE_DNS, 'snare_uuids').hex)
        return list(query_res)

    @asyncio.coroutine
    def return_uuid_stats(self, uuid):
        query_res = self.r.lrange(uuid, 0, 50)
        for (i, val) in enumerate(query_res):
            query_res[i] = json.loads(val)
        return query_res
