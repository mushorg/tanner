import asyncio
import hashlib
import logging
import os
import re

import aiohttp

from tanner.utils import patterns


class RfiEmulator:
    def __init__(self, root_dir):
        self.script_dir = root_dir + 'file/'
        self.logger = logging.getLogger('tanner.rfi_emulator.RfiEmulator')

    @asyncio.coroutine
    def download_file(self, path):
        file_name = None
        url = re.match(patterns.REMOTE_FILE_URL, path)

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
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during downloading the rfi script %s', client_error)
        else:
            yield from resp.release()
            yield from client.close()
            file_name = hashlib.md5(data.encode('utf-8')).hexdigest()
            with open(self.script_dir + file_name, 'w') as rfile:
                rfile.write(data)
        return file_name

    @asyncio.coroutine
    def get_rfi_result(self, path):
        rfi_result = None
        yield from asyncio.sleep(1)
        file_name = yield from self.download_file(path)
        if file_name is None:
            return rfi_result
        with open(self.script_dir + file_name) as script:
            script_data = script.read()
        try:
            with aiohttp.ClientSession() as session:
                resp = yield from session.post('http://127.0.0.1:8088/', data=script_data)
                rfi_result = yield from resp.json()
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during connection to php sandbox %s', client_error)
        else:
            yield from resp.release()
            yield from session.close()
        return rfi_result

    @asyncio.coroutine
    def handle(self, path, session=None):
        result = yield from self.get_rfi_result(path)
        if not result or 'stdout' not in result:
            return ''
        else:
            return result['stdout']
