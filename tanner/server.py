import asyncio
import json
import logging

import uvloop
import yarl
from aiohttp import web

from tanner import api, dorks_manager, session_manager, redis_client
from tanner.config import TannerConfig
from tanner.emulators import base
from tanner.reporting.log_local import Reporting as local_report
from tanner.reporting.log_mongodb import Reporting as mongo_report

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class TannerServer:
    def __init__(self):
        base_dir = TannerConfig.get('EMULATORS', 'root_dir')
        db_name = TannerConfig.get('SQLI', 'db_name')

        self.session_manager = session_manager.SessionManager()
        self.dorks = dorks_manager.DorksManager()
        self.api = api.Api()
        self.base_handler = base.BaseHandler(base_dir, db_name)
        self.logger = logging.getLogger(__name__)
        self.redis_client = None

    @staticmethod
    def _make_response(msg):
        response_message = dict(
            version=1,
            response=dict(message=msg)
        )
        return response_message

    @staticmethod
    async def default_handler(request):
        return web.Response(text="Tanner server")

    async def handle_event(self, request):
        data = await request.read()
        try:
            data = json.loads(data.decode('utf-8'))
            path = yarl.unquote(data['path'])
        except (TypeError, ValueError, KeyError) as error:
            self.logger.error('error parsing request: %s', data)
            response_msg = self._make_response(msg=type(error).__name__)
        else:
            session = await self.session_manager.add_or_update_session(
                data, self.redis_client
            )
            self.logger.info('Requested path %s', path)
            await self.dorks.extract_path(path, self.redis_client)
            detection = await self.base_handler.handle(data, session, path)
            session.set_attack_type(path, detection["name"])

            response_msg = self._make_response(msg=dict(detection=detection, sess_uuid=session.get_uuid()))
            self.logger.info('TANNER response %s', response_msg)

            session_data = data
            session_data['response_msg'] = response_msg

            # Log to Mongo
            if TannerConfig.get('MONGO', 'enabled') == 'True':
                db = mongo_report()
                session_id = db.create_session(session_data)
                self.logger.info("Writing session to DB: {}".format(session_id))

            if TannerConfig.get('LOCALLOG', 'enabled') == 'True':
                lr = local_report()
                lr.create_session(session_data)
        return web.json_response(response_msg)

    async def handle_api(self, request):
        api_query = request.match_info.get("api_query")
        if api_query is None:
            data = "tanner api"
        else:
            data = await self.api.handle_api_request(api_query, request.url.query, self.redis_client)
        response_msg = self._make_response(data)
        return web.json_response(response_msg)

    async def handle_dorks(self, request):
        dorks = await self.dorks.choose_dorks(self.redis_client)
        response_msg = dict(version=1, response=dict(dorks=dorks))
        return web.json_response(response_msg)

    def setup_routes(self, app):
        app.router.add_route('*', '/', self.default_handler)
        app.router.add_post('/event', self.handle_event)
        app.router.add_get('/api', self.handle_api)
        app.router.add_get('/api/{api_query}', self.handle_api)
        app.router.add_get('/dorks', self.handle_dorks)

    def create_app(self, loop):
        app = web.Application(loop=loop)
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        tanner_app = self.create_app(loop)
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client())
        host = TannerConfig.get('TANNER', 'host')
        port = TannerConfig.get('TANNER', 'port')
        web.run_app(tanner_app, host=host, port=port)
