import asyncio
import logging

from urllib.parse import unquote
from tanner.utils import patterns
from tanner.config import TannerConfig
from tanner.utils.aiodocker_helper import AIODockerHelper


class TemplateInjection:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.logger = logging.getLogger("tanner.template_injection")
        self.docker_helper = AIODockerHelper()
        self.remote_path = TannerConfig.get("REMOTE_DOCKERFILE", "GITHUB")

    async def get_injection_result(self, payload):
        execute_result = None

        # Build the custom image
        await self.docker_helper.setup_host_image(remote_path=self.remote_path, tag="template_injection:latest")

        if patterns.TEMPLATE_INJECTION_TORNADO.match(payload):
            work_dir = TannerConfig.get("DATA", "tornado")

            with open(work_dir, "r") as f:
                tornado_template = f.read().format(payload)

            cmd = ["python3", "-c", tornado_template]
            execute_result = await self.docker_helper.execute_cmd(cmd, "template_injection:latest")

            # Removing string "b''" from results
            if execute_result:
                execute_result = execute_result[2:-2]

        elif patterns.TEMPLATE_INJECTION_MAKO.match(payload):
            work_dir = TannerConfig.get("DATA", "mako")

            with open(work_dir, "r") as f:
                mako_template = f.read().format(payload)

            cmd = ["python3", "-c", mako_template]
            execute_result = await self.docker_helper.execute_cmd(cmd, "template_injection:latest")

        result = dict(value=execute_result, page=True)
        return result

    def scan(self, value):
        detection = None
        value = unquote(value)

        if patterns.TEMPLATE_INJECTION_TORNADO.match(value) or patterns.TEMPLATE_INJECTION_MAKO.match(value):
            detection = dict(name="template_injection", order=4)

        return detection

    async def handle(self, attack_params, session=None):
        attack_params[0]["value"] = unquote(attack_params[0]["value"])
        result = await self.get_injection_result(attack_params[0]["value"])
        return result
