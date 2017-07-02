import json
import logging

from aiohttp import web

class Api:
    def __init__(self, redis_client):
        self.logger = logging.getLogger('tanner.api.Api')
        self.redis_client = redis_client

    @staticmethod
    def _make_response(msg):
        response_message = dict(
            version=1,
            response=dict(message=msg)
        )
        return response_message

    async def handle_index(self, request):
        result = 'tanner api'
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snares(self, request):
        result = await self.return_snares()
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snare_info(self, request):
        snare_uuid = request.match_info['snare_uuid']
        result = await self.return_snare_info(snare_uuid, 50)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snare_stats(self, request):
        snare_uuid = request.match_info['snare_uuid']
        result = await self.return_snare_stats(snare_uuid)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_sessions(self, request):
        params = request.url.query
        applied_filters = {}
        if 'filters' in params:
            applied_filters = {filt.split(':')[0] : filt.split(':')[1] for filt in params['filters'].split()}
            if 'time_interval' in applied_filters:
                time_interval = applied_filters['time_interval']
                applied_filters['time_interval'] = {'start_time' : float(time_interval.split('-')[0]),
                                                    'end_time': float(time_interval.split('-')[1]) }
        result = await self.return_sessions(applied_filters)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_session_info(self, request):
        sess_uuid = request.match_info['sess_uuid']
        result = await self.return_session_info(sess_uuid)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def return_snares(self):
        query_res = []
        try:
            query_res = await self.redis_client.smembers('snare_ids')
            query_res = await query_res.asset()
        except asyncio_redis.NotConnectedError as connection_error:
            self.logger.error('Can not connect to redis %s', connection_error)
        return list(query_res)

    async def return_snare_stats(self, snare_uuid):
        result = {}
        sessions = await self.return_snare_info(snare_uuid)

        result['total_sessions'] = len(sessions)
        result['total_duration'] = 0
        result['attack_frequency'] = {'sqli' : 0,
                                      'lfi' : 0,
                                      'xss' : 0,
                                      'rfi' : 0,
                                      'cmd_exec' : 0}

        for sess in sessions:
            result['total_duration'] += sess['end_time'] - sess['start_time']
            for attack in sess['attack_types']:
                if attack in result['attack_frequency']:
                    result['attack_frequency'][attack] += 1

        return result

    async def return_snare_info(self, uuid, count=-1):
        query_res = []
        try:
            query_res = await self.redis_client.lrange_aslist(uuid, 0, count)
        except asyncio_redis.NotConnectedError as connection_error:
            self.logger.error('Can not connect to redis %s', connection_error)
        else:
            if not query_res:
                return 'Invalid SNARE UUID'
            for (i, val) in enumerate(query_res):
                query_res[i] = json.loads(val)
        return query_res

    async def return_session_info(self, sess_uuid, snare_uuid= None):
        query_res = []
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_snares()

        for snare_id in snare_uuids:
            sessions = await self.return_snare_info(snare_id)
            for sess in sessions:
                if sess['sess_uuid'] == sess_uuid:
                    return sess

    async def return_sessions(self, filters, snare_uuid= None):
        query_res = []
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_snares()

        matching_sessions = []
        for snare_id in snare_uuids:
            sessions = await self.return_snare_info(snare_id)
            for sess in sessions:
                is_matching_sesssion = True
                if 'user-agent' in filters:
                    if filters['user-agent'] not in sess['user-agent']:
                        is_matching_sesssion = False
                if 'peer_ip' in filters:
                    if filters['peer_ip'] != sess['peer_ip']:
                        is_matching_sesssion = False
                if 'attack_type' in filters:
                    if filters['attack_type'] not in sess['attack_types']:
                        is_matching_sesssion = False
                if 'time_interval' in filters:
                    if filters['time_interval']['end_time'] < sess['start_time'] or filters['time_interval']['start_time'] > sess['end_time']:
                        is_matching_sesssion = False
                if 'owner_type' in filters:
                    if filters['owner_type'] not in sess['owner_types']:
                        is_matching_sesssion = False

                if is_matching_sesssion:
                    matching_sessions.append(sess['sess_uuid'])
        return matching_sessions