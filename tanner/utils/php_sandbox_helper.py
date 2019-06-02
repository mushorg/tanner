import logging
import asyncio
import aiohttp
from tanner import config


class PHPSandboxHelper:
    def __init__(self, loop):
        self.logger = logging.getLogger('tanner.php_sandbox_helper.PHPSandboxHelper')
        self._loop = loop if loop is not None else asyncio.get_event_loop()

    async def injection_result(self, code):
        injection_result = None

        phpox_address = 'http://{host}:{port}'.format(host=config.TannerConfig.get('PHPOX', 'host'),
                                                      port=config.TannerConfig.get('PHPOX', 'port')
                                                      )

        try:
            async with aiohttp.ClientSession(loop=self._loop) as session:
                async with session.post(phpox_address, data=code) as resp:
                    injection_result = await resp.json()
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during connection to php sandbox %s', client_error)
        finally:
            await session.close()
        return injection_result
