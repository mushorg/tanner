import json
import logging
import operator
import asyncio
import asyncio_redis

from aiohttp import web
from tanner import redis_client
from tanner.config import TannerConfig

class Api:
    def __init__(self):
        self.logger = logging.getLogger('tanner.api.Api')
        self.redis_client = None

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
        snare_uuid = request.match_info['snare_uuid']
        params = request.url.query
        applied_filters = {'snare_uuid': snare_uuid}
        try:
            if 'filters' in params:
                for filt in params['filters'].split():
                    applied_filters[filt.split(':')[0]] = filt.split(':')[1]
                if 'start_time' in applied_filters:
                    applied_filters['start_time'] = float(applied_filters['start_time'])
                if 'end_time' in applied_filters:
                    applied_filters['end_time'] = float(applied_filters['end_time'])
        except Exception as e:
            self.logger.error('Filter error : %s' % e)
            result = 'Invalid filter definition'
        else:
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
        if sessions == 'Invalid SNARE UUID':
            return result

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
            if sessions == 'Invalid SNARE UUID':
                continue
            for sess in sessions:
                if sess['sess_uuid'] == sess_uuid:
                    return sess

    async def return_sessions(self, filters):
        query_res = []
        snare_uuids = await self.return_snares()

        matching_sessions = []
        for snare_id in snare_uuids:
            result = await self.return_snare_info(snare_id)
            if result == 'Invalid SNARE UUID':
                return 'Invalid filter : SNARE UUID'
            sessions = result
            for sess in sessions:
                match_count = 0
                for filter_name, filter_value in filters.items():
                    try:
                        if(self.apply_filter(filter_name, filter_value, sess)):
                            match_count += 1
                    except KeyError:
                        return 'Invalid filter : %s' % filter_name

                if match_count == len(filters):
                    matching_sessions.append(sess['sess_uuid']) 
                
        return matching_sessions

    def apply_filter(self, filter_name, filter_value, sess):
        available_filters = {'user_agent' : operator.contains,
                             'peer_ip' : operator.eq,
                             'attack_types' : operator.contains,
                             'possible_owners' : operator.contains,
                             'start_time' : operator.le,
                             'end_time': operator.ge,
                             'snare_uuid' : operator.eq
                            }

        try:
            if available_filters[filter_name] is operator.contains:
                return available_filters[filter_name](sess[filter_name], filter_value)
            else:
                return available_filters[filter_name](filter_value, sess[filter_name])
        except KeyError:
            raise

    async def on_shutdown(self, app):
        self.redis_client.close()

    def setup_routes(self, app):
        app.router.add_get('/', self.handle_index)
        app.router.add_get('/snares', self.handle_snares)
        app.router.add_resource('/snare/{snare_uuid}').add_route('GET', self.handle_snare_info)
        app.router.add_resource('/snare-stats/{snare_uuid}').add_route('GET', self.handle_snare_stats)
        app.router.add_resource('/{snare_uuid}/sessions').add_route('GET', self.handle_sessions)
        app.router.add_resource('/session/{sess_uuid}').add_route('GET', self.handle_session_info)

    def create_app(self, loop):
        app = web.Application(loop=loop)
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client())
        app = self.create_app(loop)
        host = '127.0.0.1' #TannerConfig.get('API', 'host')
        port = 8092 #TannerConfig.get('API', 'port')
        web.run_app(app, host=host, port=port)
