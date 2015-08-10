#!/usr/bin/python3

import time

from urllib.parse import parse_qsl

import asyncio
import aioredis
import aiohttp_session
import aiohttp_session.redis_storage

from aiohttp.web import Application, Response
from aiohttp_session import get_session, session_middleware
from aiohttp.multidict import MultiDict


@asyncio.coroutine
def event(request):
    session = yield from get_session(request)
    session['last_visit'] = time.time()
    data = yield from request.text()
    print(request.text)
    print('fff', repr(data))
    b = yield from request.payload.read()
    print('bbb', b)
    # req_params = MultiDict(parse_qsl(request.query_string))
    #post_params = MultiDict(parse_qsl(data))
    return Response(body=str.encode('dd'))


@asyncio.coroutine
def init(inner_loop):
    redis = yield from aioredis.create_pool(('localhost', 6379))
    session_storage = aiohttp_session.redis_storage.RedisStorage(
        redis,
        cookie_name="TANNER_SESSION"
    )
    app = Application(middlewares=[session_middleware(session_storage), ])

    app.router.add_route('POST', '/{version}/event', event)
    app.router.add_route('POST', '/event', event)

    srv = yield from inner_loop.create_server(
        app.make_handler(), 'localhost', 8090)
    return srv


loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
