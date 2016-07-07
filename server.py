#!/usr/bin/python3

import json
import re
import random
import urllib.parse
import os

import asyncio
import aiohttp
import aiohttp.server

import rfi_emulator
import session_manager
import xss_emulator
import dorks_manager
import lfi_emulator
import patterns


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    # Reference patterns
    patterns = {
        patterns.INDEX: dict(name='index', order=1),
        patterns.RFI_ATTACK: dict(name='rfi', order=2),
        patterns.SQLI_ATTACK: dict(name='sqli', order=2),
        patterns.LFI_ATTACK: dict(name='lfi', order=2),
        patterns.XSS_ATTACK: dict(name='xss', order=3)
    }

    session_manager = session_manager.SessionManager()

    def __init__(self, *args, **kwargs):
        super(HttpRequestHandler, self).__init__()
        self.rfi_emulator = rfi_emulator.RfiEmulator('/opt/tanner/')
        self.xss_emulator = xss_emulator.XssEmulator()
        self.lfi_emulator = lfi_emulator.LfiEmulator('/opt/tanner/')
        self.dorks = dorks_manager.DorksManager()

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
            self.dorks.extract_path(path)

            detection = dict(name='unknown', order=0)
            # dummy for wp-content
            if re.match(patterns.WORD_PRESS_CONTENT, path):
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
                    detection['payload'] = xss_result
                if detection['name'] == 'lfi':
                    lfi_result = self.lfi_emulator.handle(path)
                    detection['payload'] = lfi_result

            session.set_attack_type(path, detection['name'])
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
                dict(version=1, response=dict(dorks=self.dorks.choose_dorks())),
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
    finally:
        loop.close()
