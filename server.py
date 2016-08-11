#!/usr/bin/python3

import json
import asyncio
import logging
import logging.handlers
import aiohttp
import aiohttp.server
import dorks_manager
import session_manager
import api
import base_handler

logger = logging.getLogger('tanner')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address='/dev/log')

formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    session_manager = session_manager.SessionManager()

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__()
        self.base_handler = base_handler.BaseHandler()
        self.dorks = dorks_manager.DorksManager()
        self.api = api.Api()
        self.logger = logging.getLogger('tanner.server.HttpRequestHandler')

    def _make_response(self, msg):
        m = json.dumps(dict(
            version=1,
            response=dict(message=msg)
        )).encode('utf-8')
        return m

    @asyncio.coroutine
    def handle_event(self, data):
        try:
            data = json.loads(data.decode('utf-8'))
            path = data['path']
        except (TypeError, ValueError, KeyError) as e:
            logger.error('error parsing: {}'.format(data))
            m = self._make_response(msg=type(e).__name__)
        else:
            session = yield from HttpRequestHandler.session_manager.add_or_update_session(data)
            self.logger.info('Requested path {}'.format(path))
            self.dorks.extract_path(path)
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
            m = json.dumps(
                dict(version=1, response=dict(dorks=self.dorks.choose_dorks())),
                sort_keys=True, indent=2
            ).encode('utf-8')
        elif message.path == '/event':
            data = yield from payload.read()
            m = yield from self.handle_event(data)
        elif message.path.startswith('/api'):
            data = yield from self.api.handle_api_request(message.path)
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
        srv.close()
        loop.close()
