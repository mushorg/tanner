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
        elif query == 'snare-stats' and 'uuid' in params:
            result = await self.return_uuid_stats(params['uuid'], redis_client, 50)
        elif query == 'session-stats':
            snare_uuid_param = params['snare-uuid'] if 'snare-uuid' in params else None
            if 'sess-uuid' in params:
                result = await self.return_session_info(redis_client, params['sess-uuid'], snare_uuid_param)
            elif 'filters' in params:
                applied_filters = {filt.split(':')[0] : filt.split(':')[1] for filt in params['filters'].split()}
                result = await self.return_sessions(redis_client, applied_filters, snare_uuid_param)
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

    async def return_session_info(self, redis_client, sess_uuid, snare_uuid= None):
        query_res = []
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_stats(redis_client)

        for snare_id in snare_uuids:
            sessions = await self.return_uuid_stats(snare_id, redis_client)
            for sess in sessions:
                if sess['sess_uuid'] == sess_uuid:
                    return sess

    async def return_sessions(self, redis_client, filters, snare_uuid= None):
        valid_filters = self.validate_filters(filters)
        if validate_filters is not dict:
            return 'Invalid filters'
        query_res = []
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_stats(redis_client)

        matching_sessions = []
        for snare_id in snare_uuids:
            sessions = await self.return_uuid_stats(snare_id, redis_client)
            for sess in sessions:
                is_matching_sesssion = True
                if 'user_agent' in valid_filters:
                    if valid_filters['user_agent'] not in sess['user_agent']:
                        is_matching_sesssion = False
                if 'peer_ip' in valid_filters:
                    if valid_filters['peer_ip'] != sess['peer_ip']:
                        is_matching_sesssion = False
                if 'attack_type' in valid_filters:
                    if valid_filters['attack_type'] not in sess['attack_types']:
                        is_matching_sesssion = False
                if 'time_interval' in valid_filters:
                    if valid_filters['time_interval']['end_time'] > sess['start_time'] or valid_filters['time_interval']['start_time'] < sess['end_time']:
                        is_matching_sesssion = False
                if 'owner_type' in valid_filters:
                    if valid_filters['owner_type'] not in sess['owner_types']:
                        is_matching_sesssion = False

                if is_matching_sesssion:
                    matching_sessions.append(sess['sess_uuid'])
        return matching_sessions

    @staticmethod
    def validate_filters(filters):
        possible_filters = ['user-agent', 'peer_ip', 'attack_type', 'time_interval', 'owner_type']
        valid_filters = {}
        for key, val in filters.items():
            if key in possible_filters:
                valid_filters[key] = val

        if 'time_interval' in valid_filters and valid_filters['time_interval'] is dict and 'start_time' in valid_filters['time_interval'] and 'start_time' in valid_filters['time_interval']:
            return 'Invalid time filter'
        else:
            return valid_filters