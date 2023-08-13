import asyncio
import json
import logging
import yarl

from aiohttp import web

from tanner import dorks_manager, redis_client
from tanner.sessions import session_manager
from tanner.config import TannerConfig
from tanner.emulators import base
from tanner.reporting.log_local import Reporting as local_report
from tanner.reporting.log_mongodb import Reporting as mongo_report
from tanner.reporting.log_hpfeeds import Reporting as hpfeeds_report
from tanner import __version__ as tanner_version

class TannerServer:
    def __init__(self):
        base_dir = TannerConfig.get("EMULATORS", "root_dir")
        db_name = TannerConfig.get("SQLI", "db_name")

        self.session_manager = session_manager.SessionManager()
        self.delete_timeout = TannerConfig.get("SESSIONS", "delete_timeout")

        self.dorks = dorks_manager.DorksManager()
        self.base_handler = base.BaseHandler(base_dir, db_name)
        self.logger = logging.getLogger(__name__)
        self.redis_client = None

        if TannerConfig.get("HPFEEDS", "enabled") is True:
            self.hpf = hpfeeds_report()
            self.hpf.connect()

            if self.hpf.connected() is False:
                self.logger.warning("hpfeeds not connected - no hpfeeds messages will be created")

    @staticmethod
    def _make_response(msg):
        response_message = dict(version=tanner_version, response=dict(message=msg))
        return response_message

    @staticmethod
    async def default_handler(request):
        return web.Response(text="Tanner server")

    async def handle_event(self, request):
        data = await request.read()
        try:
            data = json.loads(data.decode("utf-8"))
            path = yarl.URL(data["path"]).human_repr()
        except (TypeError, ValueError, KeyError) as error:
            self.logger.exception("error parsing request: %s", data)
            response_msg = self._make_response(msg=type(error).__name__)
        else:
            session, _ = await self.session_manager.add_or_update_session(data, self.redis_client)
            self.logger.info("Requested path %s", path)
            await self.dorks.extract_path(path, self.redis_client)
            detection = await self.base_handler.handle(data, session)
            session.set_attack_type(path, detection["name"])

            response_msg = self._make_response(msg=dict(detection=detection, sess_uuid=session.get_uuid()))
            self.logger.info("TANNER response %s", response_msg)

            session_data = data
            session_data["response_msg"] = response_msg

            # Log to Mongo
            if TannerConfig.get("MONGO", "enabled") is True:
                db = mongo_report()
                session_id = db.create_session(session_data)
                self.logger.info("Writing session to DB: {}".format(session_id))

            # Log to hpfeeds
            if TannerConfig.get("HPFEEDS", "enabled") is True:
                if self.hpf.connected():
                    self.hpf.create_session(session_data)

            if TannerConfig.get("LOCALLOG", "enabled") is True:
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
        await self.redis_client.close()

    async def delete_sessions(self):
        try:
            while True:
                await self.session_manager.delete_old_sessions(self.redis_client)
                await asyncio.sleep(self.delete_timeout)
        except asyncio.CancelledError:
            pass

    def setup_routes(self, app):
        app.router.add_route("*", "/", self.default_handler)
        app.router.add_post("/event", self.handle_event)
        app.router.add_get("/dorks", self.handle_dorks)
        app.router.add_get("/version", self.handle_version)

    async def make_app(self):
        app = web.Application()
        app.on_shutdown.append(self.on_shutdown)
        self.setup_routes(app)
        app.on_startup.append(self.start_background_delete)
        app.on_cleanup.append(self.cleanup_background_tasks)
        return app

    async def start_background_delete(self, app):
        app["session_delete"] = asyncio.ensure_future(self.delete_sessions())

    async def cleanup_background_tasks(self, app):
        app["session_delete"].cancel()
        await app["session_delete"]

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client())

        host = TannerConfig.get("TANNER", "host")
        port = TannerConfig.get("TANNER", "port")

        web.run_app(self.make_app(), host=host, port=port)
