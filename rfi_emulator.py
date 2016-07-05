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
        file_name = None
        url_pattern = re.compile('.*=(.*(http(s){0,1}|ftp(s){0,1}):.*)')
        url = re.match(url_pattern, path)

        if url is None:
            return None
        url = url.group(1)

        if not os.path.exists(self.script_dir):
            os.makedirs(self.script_dir)

        if not (url.startswith("http") or url.startswith("ftp")):
            return None
        try:
            with aiohttp.ClientSession() as client:
                resp = yield from client.get(url)
                data = yield from resp.text()
        except Exception as e:
            print(e)
        else:
            resp.release()
            file_name = hashlib.md5(data.encode('utf-8')).hexdigest()
            with open(self.script_dir + file_name, 'w') as rfile:
                rfile.write(data)
        finally:
            return file_name

    @asyncio.coroutine
    def get_rfi_result(self, path):
        yield from asyncio.sleep(1)
        rfi_result = None

        file_name = yield from self.download_file(path)
        if file_name is None:
            return rfi_result
        with open(self.script_dir + file_name) as f:
            script_data = f.read()
        try:
            with aiohttp.ClientSession() as session:
                resp = yield from session.post('http://127.0.0.1:8088/', data=script_data)
                rfi_result = yield from resp.json()
        except Exception as e:
            print(e)
        else:
            resp.release()
        finally:
            return rfi_result

    @asyncio.coroutine
    def handle_rfi(self, path):
        result = yield from self.get_rfi_result(path)
        if not result or 'stdout' not in result:
            return ''
        else:
            return result['stdout']
