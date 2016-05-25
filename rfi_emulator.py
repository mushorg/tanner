import json
import aiohttp
import re
import hashlib
import asyncio


class RfiEmulator():

    @asyncio.coroutine
    def download_file(self, session,path):
        url_pattern = re.compile('.*=(.*(http(s){0,1}|ftp(s){0,1}):.*)')
        url = url_pattern.match(path).group(1)

        if not (url.startswith("http") or url.startswith("ftp")):
            yield None

        filename = hashlib.md5(url.encode('utf-8')).hexdigest()

        resp = yield from session.get(
            url)

        try:
            data = yield from resp.text()
            with open(filename, 'w') as f:
                f.write(data)

        finally:
            session.close()
            yield from resp.release()

    def execute_rfi(self):
        # here phpox should start to execute file ?
        pass

    @asyncio.coroutine
    def hadle_rfi(self, path):
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        asyncio.ensure_future(self.download_file(session,path))
