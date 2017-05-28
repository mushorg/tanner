import json
import logging

import asyncio_redis


class Api:
    def __init__(self):
        self.logger = logging.getLogger('tanner.api.Api')

    async def handle_api_request(self, query, params, redis_client):
        result = None

        if query == 'stats' and not params:
            result = await self.return_stats(redis_client)
        elif query == 'stats' and 'uuid' in params:
            result = await self.return_uuid_stats(params['uuid'], redis_client, 50)
        return result

    async def return_stats(self, redis_client):
        query_res = []
        try:
            query_res = await redis_client.smembers('snare_ids')
            query_res = await query_res.asset()
        except asyncio_redis.NotConnectedError as connection_error:
            self.logger.error('Can not connect to redis %s', connection_error)
        return list(query_res)

    async def return_uuid_stats(self, uuid, redis_client, count=-1):
        query_res = []
        try:
            query_res = await redis_client.lrange_aslist(uuid, 0, count)
        except asyncio_redis.NotConnectedError as connection_error:
            self.logger.error('Can not connect to redis %s', connection_error)
        else:
            if not query_res:
                return 'Invalid SNARE UUID'
            for (i, val) in enumerate(query_res):
                query_res[i] = json.loads(val)
        return query_res
