import asyncio
import asyncio_redis
import json
import logging
from redis_client import RedisClient
from urllib.parse import urlparse, parse_qs


class Api:
    def __init__(self,redis_client):
        self.logger = logging.getLogger('tanner.api.Api')
        self.redis = redis_client

    @asyncio.coroutine
    def handle_api_request(self, path):
        result = None

        parsed_path = urlparse(path)
        query = parse_qs(parsed_path.query)

        if parsed_path.path == '/api/stats' and not query:
            result = yield from self.return_stats()
        elif parsed_path.path == '/api/stats' and 'uuid' in query:
            result = yield from self.return_uuid_stats(query['uuid'], 50)
        return result

    @asyncio.coroutine
    def return_stats(self):
        query_res = []
        try:
            query_res = yield from self.redis.smembers('snare_ids')
            query_res = yield from query_res.asset()
        except asyncio_redis.ConnectionError as e:
            self.logger.error('Can not connect to redis', e)
        return list(query_res)

    @asyncio.coroutine
    def return_uuid_stats(self, uuid, n=-1):
        query_res = []
        try:
            query_res = self.redis.lrange(uuid[0], 0, n)
            query_res = yield from query_res.asset()
        except asyncio_redis.ConnectionError as e:
            self.logger.error('Can not connect to redis', e)
        else:
            if not query_res:
                return 'Invalid SNARE UUID'
            for (i, val) in enumerate(query_res):
                query_res[i] = json.loads(val)
        return query_res
