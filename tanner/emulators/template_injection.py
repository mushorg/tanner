import asyncio
import logging
import os

from urllib.parse import unquote
from tanner.utils.php_sandbox_helper import PHPSandboxHelper
from tanner.utils import patterns
from tanner.utils import docker_helper


class TemplateInjection:

    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.template_injection')
        self.helper = PHPSandboxHelper(self._loop)
        self.docker_helper = docker_helper.DockerHelper()

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

    async def get_injection_result_docker(self, payload):
        execute_result = None

        file_path = os.getcwd()
        file_path = os.path.join(file_path, 'docker/tanner/template_injection/')

        # Build the custom image
        await self.docker_helper.setup_host_image(path_to_file=file_path, tag='template_injection:latest')

        if patterns.TEMPLATE_INJECTION_TORNADO.match(payload):

            tornado_template = 'import tornado\n' \
                               'from tornado.template import Template\n' \
                               'code = "%s"\n' \
                               'result = tornado.template.Template(code)\n' \
                               'template_injection_result = result.generate()\n' \
                               'print(template_injection_result)' % payload

            execute_result = self.docker_helper.docker_client.containers.run(
                'template_injection:latest', "python3 -c \'%s\'" % tornado_template).decode('utf-8')

        elif patterns.TEMPLATE_INJECTION_MAKO.match(payload):

            mako_template = 'from mako.template import Template\n' \
                            'mako_template = Template("""%s""")\n' \
                            'template_injection_result = mako_template.render()\n' \
                            'print(template_injection_result)' % payload

            execute_result = self.docker_helper.docker_client.containers.run(
                'template_injection:latest', "python3 -c \'%s\'" % mako_template).decode('utf-8')

        result = dict(value=execute_result, page=True)
        return result

    def scan(self, value):
        detection = None
        value = unquote(value)

        if patterns.TEMPLATE_INJECTION_TWIG.match(value) or patterns.TEMPLATE_INJECTION_TORNADO.match(value) \
                or patterns.TEMPLATE_INJECTION_MAKO.match(value):
            detection = dict(name='template_injection', order=3)

        return detection

    async def handle(self, attack_params, session=None):

        attack_params[0]['value'] = unquote(attack_params[0]['value'])

        if patterns.TEMPLATE_INJECTION_TWIG.match(attack_params[0]['value']):
            result = await self.get_injection_result_twig(attack_params[0]['value'])
            if not result or 'stdout' not in result:
                return dict(status_code=504)
            return dict(value=result['stdout'], page=True)

        else:
            result = await self.get_injection_result_docker(attack_params[0]['value'])
            return result
