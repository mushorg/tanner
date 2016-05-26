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

        try:
            resp = yield from session.get(url)
            data = yield from resp.text()

        except aiohttp.errors.ClientOSError as e:
            print('bad eternal link %s: %s' % (url, e))
        else:
            yield from resp.release()
        finally:
            session.close()
            return data

    @asyncio.coroutine
    def get_rfi_result(self, script):
        loop = asyncio.get_event_loop()
        session = aiohttp.ClientSession(loop=loop)
        rfi_result = None

        bs = script.encode('utf-8')

        try:
            resp = yield from session.post('', data=bs)
            rfi_result = yield from resp.text()

        except ValueError as e:
            print('bad phpox server link : %s' % e)
        else:
            yield from resp.release()
        finally:
            session.close()
            return rfi_result



    @asyncio.coroutine
    def handle_rfi(self, path):
        data = yield from self.download_file(path)
        result = yield from self.get_rfi_result(script=data)
        return result
