import asyncio
import aiohttp_jinja2
import jinja2
import logging

from aiohttp import web
from tanner.api import api
from tanner import redis_client
from tanner.config import TannerConfig

class TannerWebServer:
    def __init__(self):
        self.logger = logging.getLogger('tanner.web.tannerwebserver')
        self.api = None
        self.redis_client = None

    @aiohttp_jinja2.template('index.html')
    async def handle_index(self, request):
        return

    @aiohttp_jinja2.template('snares.html')
    async def handle_snares(self, request):
        snares = await self.api.return_snares()
        return {
            'snares' : snares
        }

    @aiohttp_jinja2.template('snare.html')
    async def handle_snare(self, request):
        snare_uuid = request.match_info['snare_uuid']
        return{
            'snare' : snare_uuid
        }

    @aiohttp_jinja2.template('snare-stats.html')
    async def handle_snare_stats(self, request):
        snare_uuid = request.match_info['snare_uuid']
        snare_stats = await self.api.return_snare_stats(snare_uuid)
        return {
            'snare_stats' : snare_stats
        }

    @aiohttp_jinja2.template('sessions.html')
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
            sess_uuids = await self.api.return_sessions(applied_filters)
            sessions = []
            for sess_uuid in sess_uuids:
                sess = await self.api.return_session_info(sess_uuid)
                sessions.append(sess)
            result = sessions
        return {
            'sessions' : result
        }

    @aiohttp_jinja2.template('session.html')
    async def handle_session_info(self, request):
        sess_uuid = request.match_info['sess_uuid']
        session = await self.api.return_session_info(sess_uuid)
        return {
            'session' : session
        }

    def setup_routes(self, app):
        app.router.add_get('/', self.handle_index)
        app.router.add_get('/snares', self.handle_snares)
        app.router.add_resource('/snare/{snare_uuid}').add_route('GET', self.handle_snare)
        app.router.add_resource('/snare-stats/{snare_uuid}').add_route('GET', self.handle_snare_stats)
        app.router.add_resource('/session/{sess_uuid}').add_route('GET', self.handle_session_info)
        app.router.add_resource('/{snare_uuid}/sessions').add_route('GET', self.handle_sessions)
        app.router.add_static('/static/', path='tanner/web/static')

    def create_app(self, loop):
        app = web.Application(loop= loop)
        aiohttp_jinja2.setup(app,
            loader= jinja2.FileSystemLoader('tanner/web/templates'))
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client(poolsize=20))
        self.api = api.Api(self.redis_client)
        app = self.create_app(loop)
        host = TannerConfig.get('WEB', 'host')
        port = TannerConfig.get('WEB', 'port')
        web.run_app(app, host=host, port=port)
