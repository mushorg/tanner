#!/usr/bin/python3

import pickle
import json
import re
import random

import asyncio
import aiohttp
import aiohttp.server


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    # Reference patterns
    patterns = {
        re.compile('(/index.html|/)'): dict(name='index', order=1),
        re.compile('.*(=.*(http(s){0,1}|ftp(s){0,1}):).*', re.IGNORECASE): dict(name='rfi', order=2),
        re.compile('.*(select|drop|update|union|insert|alter|declare|cast)( |\().*', re.IGNORECASE): dict(
            name='sqli', order=2
        ),
        re.compile('.*(\/\.\.)*(home|proc|usr|etc)\/.*'): dict(
            name='lfi', order=2, payload='data/passwd'
        )
    }

    with open('dorks.pickle', 'rb') as fh:
        dorks = pickle.load(fh)

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        if message.path == '/dorks':
            response.add_header('Content-Type', 'application/json')
            m = json.dumps(
                dict(version=1, response=dict(dorks=random.sample(self.dorks, 50))),
                sort_keys=True, indent=2
            ).encode('utf-8')
        elif message.path == '/event':
            response.add_header('Content-Type', 'application/json')
            data = yield from payload.read()
            try:
                data = json.loads(data.decode('utf-8'))
                path = data['path']
                sensor_uuid = data['uuid'] if 'uuid' in data else None
            except (TypeError, ValueError, KeyError) as e:
                print('error parsing: {}'.format(data))
                m = json.dumps(dict(version=1, response=dict(message=type(e).__name__))).encode('utf-8')
            else:
                print(path)
                detection = dict(name='unknown', order=0)
                for pattern, patter_details in self.patterns.items():
                    if pattern.match(path):
                        if detection['order'] < patter_details['order']:
                            detection = patter_details
                if 'payload' in detection:
                    if detection['payload'].startswith('data/'):
                        with open(detection['payload'], 'rb') as fh:
                            detection['payload'] = fh.read().decode('utf-8')
                m = json.dumps(dict(version=1, response=dict(detection=detection))).encode('utf-8')
                print(m)
        else:
            response.add_header('Content-Type', 'text/plain')
            m = b''
        response.add_header('Content-Length', str(len(m)))
        response.send_headers()
        response.write(m)
        yield from response.write_eof()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=False, keep_alive=75),
        '0.0.0.0', '8090')
    srv = loop.run_until_complete(f)
    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
