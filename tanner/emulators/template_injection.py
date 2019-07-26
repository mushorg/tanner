import asyncio
import logging

from urllib.parse import unquote
from tanner.utils import patterns
from tanner.utils.aiodocker_helper import AIODockerHelper


class TemplateInjection:

    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger('tanner.template_injection')
        self.docker_helper = AIODockerHelper()

    async def get_injection_result(self, payload):
        execute_result = None
        github_remote_path = 'https://raw.githubusercontent.com/mushorg/tanner/master/docker/tanner/' \
                             'template_injection/Dockerfile'

        # Build the custom image
        await self.docker_helper.setup_host_image(
            remote_path=github_remote_path, tag='template_injection:latest')

        if patterns.TEMPLATE_INJECTION_TORNADO.match(payload):

            tornado_template = 'import tornado\n' \
                               'from tornado.template import Template\n' \
                               'code = "%s"\n' \
                               'result = tornado.template.Template(code)\n' \
                               'template_injection_result = result.generate()\n' \
                               'print(template_injection_result)' % payload

            cmd = ["python3", "-c", tornado_template]

            execute_result = await self.docker_helper.execute_cmd(cmd, 'template_injection:latest')

            # Removing string "b''" from results
            if execute_result:
                execute_result = execute_result[2:-2]

        elif patterns.TEMPLATE_INJECTION_MAKO.match(payload):

            mako_template = 'from mako.template import Template\n' \
                            'mako_template = Template("""%s""")\n' \
                            'template_injection_result = mako_template.render()\n' \
                            'print(template_injection_result)' % payload

            cmd = ["python3", "-c", mako_template]

            execute_result = await self.docker_helper.execute_cmd(cmd, 'template_injection:latest')

        result = dict(value=execute_result, page=True)
        return result

    def scan(self, value):
        detection = None
        value = unquote(value)

        if patterns.TEMPLATE_INJECTION_TORNADO.match(value) or patterns.TEMPLATE_INJECTION_MAKO.match(value):
            detection = dict(name='template_injection', order=3)

        return detection

    async def handle(self, attack_params, session=None):
        attack_params[0]['value'] = unquote(attack_params[0]['value'])
        result = await self.get_injection_result(attack_params[0]['value'])
        return result
