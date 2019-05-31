import aiohttp
import asyncio
import logging

from tanner import config
from tanner.utils import patterns


class PHPObjectInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.php_object_injection')

    async def get_injection_result(self, code):
        object_injection_result = None

        vul_code = "<?php " \
                   "class ObjectInjection {" \
                   "public $insert; " \
                   "public function __destruct() " \
                   "{ " \
                   "$var = system($this->insert, $ret); " \
                   "print $var[0]; }" \
                   "} " \
                   "$o = new ObjectInjection(); " \
                   "$o->insert = \"id\"; " \
                   "$cmd = unserialize(\"%s\");" \
                   "?>" % code

        phpox_address = 'http://{host}:{port}'.format(host=config.TannerConfig.get('PHPOX', 'host'),
                                                      port=config.TannerConfig.get('PHPOX', 'port')
                                                      )
        try:
            async with aiohttp.ClientSession(loop=self._loop) as session:
                async with session.post(phpox_address, data=vul_code) as resp:
                    object_injection_result = await resp.json()
        except aiohttp.ClientError as client_error:
            self.logger.error('Error during connection to php sandbox %s', client_error)
        else:
            await session.close()
        return object_injection_result

    def scan(self, value):
        detection = None
        if patterns.PHP_OBJECT_INJECTION.match(value):
            detection = dict(name='php_object_injection', order=3)
        return detection

    async def handle(self, attack_params):
        result = await self.get_injection_result(attack_params[0]['value'])
        if not result or 'stdout' not in result:
            return dict(status_code=504)
        return dict(value=result['stdout'], page=False)
