import aiohttp
import re
import asyncio


class RfiEmulator:

    @asyncio.coroutine
    def download_file(self, path):
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        data = None
        url_pattern = re.compile('.*=(.*(http(s){0,1}|ftp(s){0,1}):.*)')
        url = url_pattern.match(path).group(1)

        if not (url.startswith("http") or url.startswith("ftp")):
            yield None

        resp = yield from session.get(url)

        try:
            data = yield from resp.text()

        finally:
            session.close()
            yield from resp.release()
            return data

    @asyncio.coroutine
    def get_rfi_result(self, script):
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        bs = script.encode('utf-8')
        resp = yield from session.post('', data=bs)

        try:
            resp_txt = yield from resp.text()
            print(resp_txt)
        finally:
            session.close()
            yield from resp.release()

    @asyncio.coroutine
    def handle_rfi(self, path):
        data = yield from self.download_file(path)
        yield from self.get_rfi_result(script=data)
