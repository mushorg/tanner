#!/usr/bin/python3

import json
import asyncio
import logging
import aiohttp
import aiohttp.server
import asyncio_redis
import dorks_manager
import session_manager
import api
import base_handler
import logger
import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
logger = logger.Logger.create_logger('tanner.log', 'tanner')


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    session_manager = session_manager.SessionManager()
    base_handler = base_handler.BaseHandler()
    dorks = dorks_manager.DorksManager()
    loop = asyncio.get_event_loop()
    redis_client = loop.run_until_complete(
        asyncio_redis.Pool.create(host='localhost', port=6379, poolsize=1000, loop=loop))

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__()
        self.api = api.Api()
        self.logger = logging.getLogger('tanner.server.HttpRequestHandler')

    @staticmethod
    def _make_response(msg):
        m = json.dumps(dict(
            version=1,
            response=dict(message=msg)
        )).encode('utf-8')
        return m

    @asyncio.coroutine
    def handle_event(self, data, redis_client):
        try:
            data = json.loads(data.decode('utf-8'))
            path = data['path']
        except (TypeError, ValueError, KeyError) as e:
            self.logger.error('error parsing: {}'.format(data))
            m = self._make_response(msg=type(e).__name__)
        else:
            session = yield from HttpRequestHandler.session_manager.add_or_update_session(data)
            self.logger.info('Requested path {}'.format(path))
            yield from self.dorks.extract_path(path, redis_client)
            detection = yield from self.base_handler.handle(data, session, path)
            session.set_attack_type(path, detection['name'])
            m = self._make_response(msg=dict(detection=detection))
            self.logger.info('TANNER response {}'.format(m))
            return m

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        if message.path == '/dorks':
            dorks = yield from self.dorks.choose_dorks(self.redis_client)
            m = json.dumps(
                dict(version=1, response=dict(dorks=dorks)),
                sort_keys=True, indent=2
            ).encode('utf-8')
        elif message.path == '/event':
            data = yield from payload.read()
            m = yield from self.handle_event(data, self.redis_client)
        elif message.path.startswith('/api'):
            data = yield from self.api.handle_api_request(message.path, self.redis_client)
            m = self._make_response(data)
        else:
            m = self._make_response(msg='')

        response.add_header('Content-Type', 'application/json')
        response.add_header('Content-Length', str(len(m)))
        response.send_headers()
        response.write(m)
        yield from response.write_eof()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=False, keep_alive=75),
        '0.0.0.0', int('8090'))
    srv = loop.run_until_complete(f)
    logger.info('serving on {}'.format(srv.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        HttpRequestHandler.redis_client.close()
        loop.stop()
        loop.close()
