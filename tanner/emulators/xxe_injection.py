import asyncio
import logging

from tanner.config import TannerConfig
from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns


class XXEInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.xxe_injection')
        self.helper = PHPSandboxHelper(self._loop)

    async def get_injection_result(self, code):

        vul_code = '''<?php
                        libxml_disable_entity_loader (false);
                        $xml = \'%s\';
                        $dom = new DOMDocument();
                        $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
                        $data = simplexml_import_dom($dom);

                        echo $data;
                      ?>''' % code

        xxe_injection_result = await self.helper.get_result(vul_code)

        return xxe_injection_result

    def scan(self, value):
        detection = None
        if patterns.XXE_INJECTION.match(value):
            detection = dict(name='xxe_injection', order=3)
        return detection

    async def handle(self, attack_params):
        result = await self.get_injection_result(attack_params[0]['value'])
        if not result or 'stdout' not in result:
            return dict(status_code=504)

        if TannerConfig.get('XXE_INJECTION', 'OUT_OF_BAND'):
            return dict(value='', page=False)
        return dict(value=result['stdout'], page=False)
