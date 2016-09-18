#!/usr/bin/python3

import asyncio
import json
import logging
from urllib.parse import unquote

import aiohttp
import aiohttp.server
import asyncio_redis
import uvloop

from tanner import api, dorks_manager, session_manager
from tanner.emulators import base
from tanner.utils import logger

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
LOGGER = logger.Logger.create_logger('tanner.log', 'tanner')


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    redis_client = None
    session_manager = session_manager.SessionManager()
    dorks = dorks_manager.DorksManager()

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__()
        self.api = api.Api()
        self.base_handler = base.BaseHandler()
        self.logger = logging.getLogger('tanner.server.HttpRequestHandler')

    @staticmethod
    def _make_response(msg):
        response_message = json.dumps(dict(
            version=1,
            response=dict(message=msg)
        )).encode('utf-8')
        return response_message

    @asyncio.coroutine
    def handle_event(self, data, redis_client):
        try:
            data = json.loads(data.decode('utf-8'))
            path = unquote(data['path'])
        except (TypeError, ValueError, KeyError) as error:
            self.logger.error('error parsing request: %s', data)
            response_msg = self._make_response(msg=type(error).__name__)
        else:
            session = yield from HttpRequestHandler.session_manager.add_or_update_session(
                data, self.redis_client
            )
            self.logger.info('Requested path %s', path)
            yield from self.dorks.extract_path(path, redis_client)
            detection = yield from self.base_handler.handle(data, session, path)
            session.set_attack_type(path, detection['name'])
            response_msg = self._make_response(msg=dict(detection=detection))
            self.logger.info('TANNER response %s', response_msg)
            return response_msg

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        if message.path == '/dorks':
            dorks = yield from self.dorks.choose_dorks(self.redis_client)
            response_msg = json.dumps(
                dict(version=1, response=dict(dorks=dorks)),
                sort_keys=True, indent=2
            ).encode('utf-8')
        elif message.path == '/event':
            data = yield from payload.read()
            response_msg = yield from self.handle_event(data, self.redis_client)
        elif message.path.startswith('/api'):
            data = yield from self.api.handle_api_request(message.path, self.redis_client)
            response_msg = self._make_response(data)
        else:
            response_msg = self._make_response(msg='')

        response.add_header('Content-Type', 'application/json')
        response.add_header('Content-Length', str(len(response_msg)))
        response.send_headers()
        response.write(response_msg)
        yield from response.write_eof()


@asyncio.coroutine
def get_redis_client():
    try:
        redis_client = yield from asyncio.wait_for(asyncio_redis.Pool.create(
            host='localhost', port=6379, poolsize=80), timeout=1)
    except asyncio.TimeoutError as timeout:
        LOGGER.error('Problem with redis connection. Please, check your redis server. %s', timeout)
        exit()
    else:
        HttpRequestHandler.redis_client = redis_client


def run_server():
    loop = asyncio.get_event_loop()
    if HttpRequestHandler.redis_client is None:
        loop.run_until_complete(get_redis_client())
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=False, keep_alive=75),
        '0.0.0.0', int('8090'))
    srv = loop.run_until_complete(f)
    LOGGER.info('serving on %s', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        HttpRequestHandler.redis_client.close()
        srv.close()
        loop.run_until_complete(srv.wait_closed())
        loop.close()
