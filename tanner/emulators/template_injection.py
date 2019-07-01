import asyncio
import logging
import os

from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns
from jinja2 import Environment

Jinja2 = Environment()


class TemplateInjection:

    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.template_injection')
        self.helper = PHPSandboxHelper(self._loop)

    async def get_injection_result_twig(self, payload):

        path_to_vendor = os.getcwd() + '/vendor'

        twig_template = """<?php
                            require '%s/autoload.php';

                            use Twig\Environment;
                            use \Twig\Loader\ArrayLoader;
 
                            $name = '%s';
                            $loader = new ArrayLoader(array('index' => $name,));
                            $twig = new Environment($loader);
                            echo $twig->render('index');
                           ?>""" % (path_to_vendor, payload)

        template_injection_result = await self.helper.get_result(twig_template)

        return template_injection_result

    def scan(self, value):
        detection = None

        if patterns.TEMPLATE_INJECTION_TWIG.match(value):
            detection = dict(name='template_injection', order=3)
        return detection

    async def handle(self, attack_params, session=None):
        result = await self.get_injection_result_twig(attack_params[0]['value'])
        if not result or 'stdout' not in result:
            return dict(status_code=504)
        return dict(value=result['stdout'], page=False)
