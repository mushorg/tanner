import asyncio
import logging

from tanner.config import TannerConfig
from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns


class TwigTemplateInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger("tanner.twig_template_injection")
        self.helper = PHPSandboxHelper(self._loop)
        self.autoloader = TannerConfig.get("TWIG_PATH", "autoloader")
        self.stringloader = TannerConfig.get("TWIG_PATH", "stringloader")

    async def get_injection_result(self, code):
        """
        Injects the code from attacker to vulnerable code and get emulation results from php sandbox.
        :param code (str): Input payload from attacker
        :return: twig_injection_result (dict): file_md5 (md5 hash), stdout (injection result) as keys.
        """

        vul_code = """
        <?php

            require '%s';
            require '%s';

            Twig_Autoloader::register();
            $loader = new Twig_Loader_String();
            $twig = new Twig_Environment($loader);
            $twig->addExtension(new \\Twig\\Extension\\StringLoaderExtension());
            $payload = "%s";
            $result = $twig->render($payload);
            echo $result;
        ?>
        """ % (
            self.autoloader,
            self.stringloader,
            code,
        )

        self.logger.debug(
            "Getting the twig injection results of %s from php sandbox", code
        )
        twig_injection_result = await self.helper.get_result(vul_code)

        return twig_injection_result

    def scan(self, value):
        """
        Scans the input payload to detect attack using regex
        :param value (str): code from attacker
        :return: detection (dict): name (attack name), order (attack order) as keys
        """

        detection = None
        if patterns.TEMPLATE_INJECTION_TORNADO.match(value):
            detection = dict(name="twig_template_injection", order=3)
        return detection

    async def handle(self, attack_params, session=None):
        attack_params[0]['value'] = unquote(attack_params[0]['value'])
        result = await self.get_injection_result(attack_params[0]['value'])
        return result
