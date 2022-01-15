import asyncio
import logging

from aiohttp import web
from aiohttp.web import middleware

from tanner.api import api
from tanner import redis_client
from tanner.config import TannerConfig
from tanner.utils.api_key_generator import generate

import jwt
from jwt.exceptions import DecodeError, InvalidSignatureError


class ApiServer:
    def __init__(self):
        self.logger = logging.getLogger("tanner.api.ApiServer")
        self.api = None

    @staticmethod
    def _make_response(msg):
        response_message = dict(version=1, response=dict(message=msg))
        return response_message

    async def handle_index(self, request):
        result = "tanner api"
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snares(self, request):
        result = await self.api.return_snares()
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snare_info(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        result = await self.api.return_snare_info(snare_uuid, 50)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_snare_stats(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        result = await self.api.return_snare_stats(snare_uuid)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_sessions(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        params = request.url.query
        applied_filters = {"snare_uuid": snare_uuid}
        try:
            if "filters" in params:
                for filt in params["filters"].split():
                    applied_filters[filt.split(":")[0]] = filt.split(":")[1]
                if "start_time" in applied_filters:
                    applied_filters["start_time"] = float(applied_filters["start_time"])
                if "end_time" in applied_filters:
                    applied_filters["end_time"] = float(applied_filters["end_time"])
        except Exception as e:
            self.logger.exception("Filter error : %s" % e)
            result = "Invalid filter definition"
        else:
            sessions = await self.api.return_sessions(applied_filters)
            sess_uuids = [sess["sess_uuid"] for sess in sessions]
            result = sess_uuids
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def handle_session_info(self, request):
        sess_uuid = request.match_info["sess_uuid"]
        result = await self.api.return_session_info(sess_uuid)
        response_msg = self._make_response(result)
        return web.json_response(response_msg)

    async def on_shutdown(self, app):
        self.redis_client.close()

    @middleware
    async def auth(self, request, handler):
        resp = await handler(request)
        auth_key = request.query.get("key")
        try:
            decoded = jwt.decode(auth_key, TannerConfig.get("API", "auth_signature"), algorithm="HS256")
        except (DecodeError, InvalidSignatureError):
            return web.Response(body="401: Unauthorized")
        return resp

    def setup_routes(self, app):
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/snares", self.handle_snares)
        app.router.add_resource("/snare/{snare_uuid}").add_route("GET", self.handle_snare_info)
        app.router.add_resource("/snare-stats/{snare_uuid}").add_route("GET", self.handle_snare_stats)
        app.router.add_resource("/{snare_uuid}/sessions").add_route("GET", self.handle_sessions)
        app.router.add_resource("/session/{sess_uuid}").add_route("GET", self.handle_session_info)

    async def make_app(self, auth=False):
        if auth:
            app = web.Application(middlewares=[self.auth])
        else:
            app = web.Application()
        app.on_shutdown.append(self.on_shutdown)
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client(poolsize=20))
        self.api = api.Api(self.redis_client)
        set_auth = TannerConfig.get("API", "auth")

        host = TannerConfig.get("API", "host")
        port = int(TannerConfig.get("API", "port"))

        if set_auth:
            key = generate()
            print("API_KEY for full access:", key)

        web.run_app(self.make_app(auth=set_auth), host=host, port=port)
