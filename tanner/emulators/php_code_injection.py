import asyncio
import logging

from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns


class PHPCodeInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger("tanner.php_code_injection")
        self.helper = PHPSandboxHelper(self._loop)

    async def get_injection_result(self, code):
        vul_code = "<?php eval('$a = {code}'); ?>".format(code=code)
        self.logger.debug("Getting the code injection results of %s from php sandbox", code)
        code_injection_result = await self.helper.get_result(vul_code)

        return code_injection_result

    def scan(self, value):
        detection = None
        if patterns.PHP_CODE_INJECTION.match(value):
            detection = dict(name="php_code_injection", order=3)
        return detection

    async def handle(self, attack_params, session=None):
        result = await self.get_injection_result(attack_params[0]["value"])
        if not result or "stdout" not in result:
            self.logger.exception("Error while getting the injection results from php sandbox..")
            return dict(status_code=504)
        return dict(value=result["stdout"], page=False)
