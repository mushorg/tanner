import asyncio
import asyncio_redis
import json
import logging
from urllib.parse import urlparse, parse_qs


class Api:
    def __init__(self):
        self.logger = logging.getLogger('tanner.api.Api')

    @asyncio.coroutine
    def handle_api_request(self, path, redis_client):
        result = None

        parsed_path = urlparse(path)
        query = parse_qs(parsed_path.query)

        if parsed_path.path.startswith('/api/stats') and not query:
            result = yield from self.return_stats(redis_client)
        elif parsed_path.path == '/api/stats' and 'uuid' in query:
            result = yield from self.return_uuid_stats(query['uuid'], redis_client, 50)
        return result

    @asyncio.coroutine
    def return_stats(self, redis_client):
        query_res = []
        try:
            query_res = yield from redis_client.smembers('snare_ids')
            query_res = yield from query_res.asset()
        except asyncio_redis.NotConnectedError as e:
            self.logger.error('Can not connect to redis', e)
        return list(query_res)

    @asyncio.coroutine
    def return_uuid_stats(self, uuid, redis_client, n=-1):
        query_res = []
        try:
            query_res = yield from redis_client.lrange_aslist(uuid[0], 0, n)
        except asyncio_redis.NotConnectedError as e:
            self.logger.error('Can not connect to redis', e)
        else:
            if not query_res:
                return 'Invalid SNARE UUID'
            for (i, val) in enumerate(query_res):
                query_res[i] = json.loads(val)
        return query_res
