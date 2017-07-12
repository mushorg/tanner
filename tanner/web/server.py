import asyncio
import aiohttp_jinja2
import jinja2
import logging

from aiohttp import web
from tanner import api, redis_client
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

    def setup_routes(self, app):
        app.router.add_get('/', self.handle_index)
        app.router.add_get('/snares', self.handle_snares)

    def create_app(self, loop):
        app = web.Application(loop= loop)
        aiohttp_jinja2.setup(app,
            loader= jinja2.FileSystemLoader('templates'))
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client())
        self.api = api.Api(self.redis_client)
        app = self.create_app(loop)
        web.run_app(app, host= '0.0.0.0', port= 8091)

TannerWebServer().start()