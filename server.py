#!/usr/bin/python3

import json
import re

import asyncio
import aiohttp
import aiohttp.server


class HttpRequestHandler(aiohttp.server.ServerHttpProtocol):
    patterns = {
        re.compile(r'/index.html'): 'index',
        re.compile(r'.*(=.*(http(s){0,1}|ftp(s){0,1}):).*', re.IGNORECASE): 'rfi',
    }

    @asyncio.coroutine
    def handle_request(self, message, payload):
        response = aiohttp.Response(
            self.writer, 200, http_version=message.version
        )
        data = yield from payload.read()
        # print(repr(data))
        path = json.loads(data.decode('utf-8'))['path']
        print(path)
        name = None
        for pattern, name in self.patterns.items():
            if pattern.match(path):
                print(name)
            else:
                print('no match')
        m = json.dumps(dict(version=1, response=dict(detection=name))).encode('utf-8')
        response.add_header('Content-Type', 'application/json')
        response.add_header('Content-Length', str(len(m)))
        response.send_headers()
        response.write(m)
        yield from response.write_eof()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: HttpRequestHandler(debug=True, keep_alive=75),
        '0.0.0.0', '8090')
    srv = loop.run_until_complete(f)
    print('serving on', srv.sockets[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
