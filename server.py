#!/usr/bin/python3

import pickle
import json
import re
import random
import urllib.parse
import os

import asyncio
import aiohttp
import aiohttp.server

from rfi_emulator import RfiEmulator
from session_manager import SessionManager
from xss_emulator import XssEmulator
from lfi_emulator import LfiEmulator


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    # Reference patterns
    patterns = {
        re.compile('(/index.html|/)'): dict(name='index', order=1),
        re.compile('.*(=.*(http(s){0,1}|ftp(s){0,1}):).*', re.IGNORECASE): dict(name='rfi', order=2),
        re.compile('.*(select|drop|update|union|insert|alter|declare|cast)( |\().*', re.IGNORECASE): dict(
            name='sqli', order=2
        ),
        re.compile('.*(\/\.\.)*(home|proc|usr|etc)\/.*'): dict(
            name='lfi', order=2
        ),
        re.compile('.*<(.|\n)*?>'): dict(name='xss', order=2)

    }

    with open('dorks.pickle', 'rb') as fh:
        dorks = pickle.load(fh)

    session_manager = SessionManager()

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__()
        self.rfi_emulator = RfiEmulator()
        self.xss_emulator = XssEmulator()
        self.lfi_emulator = LfiEmulator(os.getcwd())

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
            sensor_uuid = data['uuid'] if 'uuid' in data else None
        except (TypeError, ValueError, KeyError) as e:
            print('error parsing: {}'.format(data))
            m = self._make_response(msg=type(e).__name__)
        else:
            session = yield from HttpRequestHandler.session_manager.add_or_update_session(data)
            print(path)
            detection = dict(name='unknown', order=0)
            # dummy for wp-content
            if re.match(r'/wp-content/.*', path):
                m = self._make_response(msg=dict(detection={'name': 'wp-content', 'order': 1}))
                return m

            if data['method'] == 'POST':
                xss_result = self.xss_emulator.handle(session, None, data)
                if xss_result:
                    detection = {'name': 'xss', 'order': 2, 'payload': xss_result}
            else:
                path = urllib.parse.unquote(path)
                for pattern, patter_details in self.patterns.items():
                    if pattern.match(path):
                        if detection['order'] < patter_details['order']:
                            detection = patter_details

                if detection['name'] == 'rfi':
                    rfi_emulation_result = yield from self.rfi_emulator.handle_rfi(path)
                    detection['payload'] = rfi_emulation_result
                if detection['name'] == 'xss':
                    xss_result = self.xss_emulator.handle(session, path)
                if detection['name'] == 'lfi':
                    lfi_result = self.lfi_emulator.handle(path)
                    detection['payload'] = lfi_result

            m = self._make_response(msg=dict(detection=detection))
            print(m)

            return m

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        if message.path == '/dorks':
            m = json.dumps(
                dict(version=1, response=dict(dorks=random.sample(self.dorks, 50))),
                sort_keys=True, indent=2
            ).encode('utf-8')
        elif message.path == '/event':
            data = yield from payload.read()
            m = yield from self.handle_event(data)
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

    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
