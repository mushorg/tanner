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
from tanner.reporting.log_hpfeeds import Reporting as hpfeeds_report
from tanner import __version__ as tanner_version

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class TannerServer:
    def __init__(self):
        base_dir = TannerConfig.get('EMULATORS', 'root_dir')
        db_name = TannerConfig.get('SQLI', 'db_name')

        self.session_manager = session_manager.SessionManager()
        self.dorks = dorks_manager.DorksManager()
        self.base_handler = base.BaseHandler(base_dir, db_name)
        self.logger = logging.getLogger(__name__)
        self.redis_client = None

        if TannerConfig.get('HPFEEDS', 'enabled'):
            self.hpf = hpfeeds_report()
            self.hpf.connect()

            if self.hpf.connected() is False:
                self.logger.warning('hpfeeds not connected - no hpfeeds messages will be created')

    @staticmethod
    def _make_response(msg):
        response_message = dict(
            version=tanner_version,
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
            detection = await self.base_handler.handle(data, session)
            session.set_attack_type(path, detection["name"])

            response_msg = self._make_response(msg=dict(detection=detection, sess_uuid=session.get_uuid()))
            self.logger.info('TANNER response %s', response_msg)

            session_data = data
            session_data['response_msg'] = response_msg

            # Log to Mongo
            if TannerConfig.get('MONGO', 'enabled'):
                db = mongo_report()
                session_id = db.create_session(session_data)
                self.logger.info("Writing session to DB: {}".format(session_id))

            # Log to hpfeeds
            if TannerConfig.get('HPFEEDS', 'enabled'):
                if self.hpf.connected():
                    self.hpf.create_session(session_data)

            if TannerConfig.get('LOCALLOG', 'enabled'):
                lr = local_report()
                lr.create_session(session_data)

        return web.json_response(response_msg)

    async def handle_dorks(self, request):
        dorks = await self.dorks.choose_dorks(self.redis_client)
        response_msg = dict(version=tanner_version, response=dict(dorks=dorks))
        return web.json_response(response_msg)

    async def handle_version(self, request):
        response_msg = dict(version=tanner_version)
        return web.json_response(response_msg)

    async def on_shutdown(self, app):
        await self.session_manager.delete_sessions_on_shutdown(self.redis_client)
        self.redis_client.close()

    def setup_routes(self, app):
        app.router.add_route('*', '/', self.default_handler)
        app.router.add_post('/event', self.handle_event)
        app.router.add_get('/dorks', self.handle_dorks)
        app.router.add_get('/version', self.handle_version)

    def create_app(self, loop):
        app = web.Application(loop=loop)
        app.on_shutdown.append(self.on_shutdown)
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client())
        app = self.create_app(loop)
        host = TannerConfig.get('TANNER', 'host')
        port = TannerConfig.get('TANNER', 'port')
        web.run_app(app, host=host, port=int(port))
