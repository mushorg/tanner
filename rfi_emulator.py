import aiohttp
import re
import asyncio
import hashlib
import os


class RfiEmulator:
    def __init__(self, root_dir):
        self.script_dir = root_dir + 'file/'

    @asyncio.coroutine
    def download_file(self, path):
        loop = asyncio.get_event_loop()
        data = None
        filename = None
        url_pattern = re.compile('.*=(.*(http(s){0,1}|ftp(s){0,1}):.*)')
        url = url_pattern.match(path).group(1)

        if not os.path.exists(self.script_dir):
            os.makedirs(self.script_dir)

        if not (url.startswith("http") or url.startswith("ftp")):
            return None

        with aiohttp.ClientSession(loop=loop) as session:
            resp = yield from session.get(url)
            try:
                data = yield from resp.text()
            except Exception as e:
                print('Error with response %s' % e)
            else:
                filename = hashlib.md5(data.encode('utf-8')).hexdigest()
                with open(self.script_dir + filename, 'w') as rfile:
                    rfile.write(data)
            finally:
                yield from resp.release()
                return filename

    @asyncio.coroutine
    def get_rfi_result(self, file_path):
        loop = asyncio.get_event_loop()
        rfi_result = None

        if not os.path.exists(self.script_dir + file_path):
            return None

        with open(self.script_dir + file_path) as rfile:
            script = rfile.read()

        with aiohttp.ClientSession(loop=loop) as session:
            resp = yield from session.post('http://127.0.0.1:8088/', data=script)
            try:
                rfi_result = yield from resp.json()
            except Exception as e:
                print('Error with response %s' % e)
            else:
                yield from resp.release()
            finally:
                return rfi_result

    @asyncio.coroutine
    def handle_rfi(self, path):
        filename = yield from self.download_file(path)
        result = yield from self.get_rfi_result(filename)
        if not result or 'stdout' not in result:
            return ''
        return result['stdout']
