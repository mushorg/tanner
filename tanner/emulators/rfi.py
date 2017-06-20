import asyncio
import ftplib
import hashlib
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import yarl

from tanner.utils import patterns


class RfiEmulator:
    def __init__(self, root_dir, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.script_dir = os.path.join(root_dir, 'files')
        self.logger = logging.getLogger('tanner.rfi_emulator.RfiEmulator')

    async def download_file(self, path):
        file_name = None
        url = re.match(patterns.REMOTE_FILE_URL, path)

        if url is None:
            return None
        url = url.group(1)
        url = yarl.URL(url)

        if not os.path.exists(self.script_dir):
            os.makedirs(self.script_dir)

        if url.scheme == "ftp":
            pool = ThreadPoolExecutor()
            ftp_future = self._loop.run_in_executor(pool, self.download_file_ftp, url)
            file_name = await ftp_future

        else:
            try:
                async with aiohttp.ClientSession(loop=self._loop) as client:
                    async with client.get(url) as resp:
                        data = await resp.text()
            except aiohttp.ClientError as client_error:
                self.logger.error('Error during downloading the rfi script %s', client_error)
            else:
                tmp_filename = url.name + str(time.time())
                file_name = hashlib.md5(tmp_filename.encode('utf-8')).hexdigest()
                with open(os.path.join(self.script_dir, file_name), 'bw') as rfile:
                    rfile.write(data.encode('utf-8'))
        return file_name

    def download_file_ftp(self, url):
        host = url.host
        ftp_path = url.path.rsplit('/', 1)[0][1:]
        name = url.name
        try:
            ftp = ftplib.FTP(host)
            ftp.login()
            ftp.cwd(ftp_path)
            tmp_filename = name + str(time.time())
            file_name = hashlib.md5(tmp_filename.encode('utf-8')).hexdigest()
            with open(file_name, 'wb') as ftp_script:
                ftp.retrbinary('RETR %s' % name, ftp_script.write)
        except ftplib.all_errors as ftp_errors:
            self.logger.error("Problem with ftp download %s", ftp_errors)
            return None
        else:
            return file_name

    async def get_rfi_result(self, path):
        rfi_result = None
        await asyncio.sleep(1, loop=self._loop)
        file_name = await self.download_file(path)
        if file_name is None:
            return rfi_result
        with open(os.path.join(self.script_dir, file_name), 'br') as script:
            script_data = script.read()
        try:
            async with aiohttp.ClientSession(loop=self._loop) as session:
                async with session.post('http://127.0.0.1:8088/', data=script_data) as resp:
                    rfi_result = await resp.json()
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during connection to php sandbox %s', client_error)
        else:
            await resp.release()
            await session.close()
        return rfi_result

    def scan(self, value):
        detection = None
        if patterns.RFI_ATTACK.match(value):
            detection = dict(name= 'rfi', order= 2)
        return detection

    async def handle(self, attack_params, session=None):
        result = await self.get_rfi_result(attack_params[0]['value'])
        if not result or 'stdout' not in result:
            return ''
        else:
            return result['stdout']
