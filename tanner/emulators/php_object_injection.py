import asyncio
import logging

from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns


class PHPObjectInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.php_object_injection')
        self.helper = PHPSandboxHelper(self._loop)

    async def get_injection_result(self, code):

        vul_code = "<?php " \
                   "class ObjectInjection { " \
                   "public $insert; " \
                   "public function __destruct() { " \
                   "$var = system($this->insert, $ret);" \
                   "print $var[0];" \
                   "$this->date = date('d-m-y');" \
                   "$this->filename = '/tmp/logs/' . $this->date;" \
                   "file_put_contents($this->filename, $var[0], FILE_APPEND);" \
                   "}} " \
                   "$cmd = unserialize(\'%s\');" \
                   "?>" % code

        object_injection_result = await self.helper.get_result(vul_code)

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
