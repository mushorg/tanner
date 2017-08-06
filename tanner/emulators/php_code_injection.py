import aiohttp
import asyncio
import logging

from tanner.utils import patterns

class PHPCodeInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.php_code_injecton')

    async def get_injection_result(self, code): 
        code_injection_result = None
        code = '<?php {code} ?>'.format(code=code)
        try:
            async with aiohttp.ClientSession(loop=self._loop) as session:
                async with session.post('http://127.0.0.1:8088/', data=code) as resp:
                    code_injection_result = await resp.json()
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during connection to php sandbox %s', client_error)
        else:
            await resp.release()
            await session.close()
        return code_injection_result

    def scan(self, value):
        detection = None
        if patterns.PHP_CODE_INJECTION.match(value):
            detection = dict(name='php_code_injection', order=3)
        return detection

    async def handle(self, attack_params, session=None):
        result = await self.get_injection_result(attack_params[0]['value'])
        if not result or 'stdout' not in result:
            return ''
        return result['stdout']
