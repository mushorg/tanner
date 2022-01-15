import asyncio
import logging
import aiohttp_jinja2
import jinja2

from aiohttp import web
from tanner.api import api
from tanner import redis_client
from tanner.config import TannerConfig
from tanner import __version__ as tanner_version


class TannerWebServer:
    def __init__(self):
        self.logger = logging.getLogger("tanner.web.tannerwebserver")
        self.api = None
        self.redis_client = None

    @aiohttp_jinja2.template("index.html")
    async def handle_index(self, request):
        snares = await self.api.return_snares()
        latest_session = await self.api.return_latest_session()
        count = len(snares)
        return {"count": count, "l_session": latest_session, "version": tanner_version}

    @aiohttp_jinja2.template("snares.html")
    async def handle_snares(self, request):
        snares = await self.api.return_snares()
        return {"snares": snares}

    @aiohttp_jinja2.template("snare.html")
    async def handle_snare(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        return {"snare": snare_uuid}

    @aiohttp_jinja2.template("snare-stats.html")
    async def handle_snare_stats(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        snare_stats = await self.api.return_snare_stats(snare_uuid)
        return {"snare_stats": snare_stats}

    @aiohttp_jinja2.template("sessions.html")
    async def handle_sessions(self, request):
        snare_uuid = request.match_info["snare_uuid"]
        page_id = int(request.match_info["page_id"])
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
            result = sessions[15 * (page_id - 1) : 15 * page_id]
            next_val = None
            pre_val = None
            if page_id * 15 <= len(sessions):
                next_val = "/{snare_uuid}/sessions/page/{page_id}".format(
                    snare_uuid=snare_uuid, page_id=str(page_id + 1)
                )
                if len(applied_filters) > 1:
                    next_val += "?filters={filters}".format(filters=params["filters"])
            if page_id > 1:
                pre_val = "/{snare_uuid}/sessions/page/{page_id}".format(
                    snare_uuid=snare_uuid, page_id=str(page_id - 1)
                )
                if len(applied_filters) > 1:
                    pre_val += "?filters={filters}".format(filters=params["filters"])

        return {"sessions": result, "next_val": next_val, "pre_val": pre_val}

    @aiohttp_jinja2.template("session.html")
    async def handle_session_info(self, request):
        sess_uuid = request.match_info["sess_uuid"]
        session = await self.api.return_session_info(sess_uuid)
        return {"session": session}

    async def on_shutdown(self, app):
        await self.redis_client.close()

    def setup_routes(self, app):
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/snares", self.handle_snares)
        app.router.add_resource("/snare/{snare_uuid}").add_route("GET", self.handle_snare)
        app.router.add_resource("/snare-stats/{snare_uuid}").add_route("GET", self.handle_snare_stats)
        app.router.add_resource("/session/{sess_uuid}").add_route("GET", self.handle_session_info)
        app.router.add_resource("/{snare_uuid}/sessions/page/{page_id}").add_route("GET", self.handle_sessions)
        app.router.add_static("/static/", path="tanner/web/static")

    async def make_app(self):
        app = web.Application()
        aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("tanner/web/templates"))
        app.on_shutdown.append(self.on_shutdown)
        self.setup_routes(app)
        return app

    def start(self):
        loop = asyncio.get_event_loop()
        self.redis_client = loop.run_until_complete(redis_client.RedisClient.get_redis_client(poolsize=20))
        self.api = api.Api(self.redis_client)

        host = TannerConfig.get("WEB", "host")
        port = int(TannerConfig.get("WEB", "port"))
        web.run_app(self.make_app(), host=host, port=port)
