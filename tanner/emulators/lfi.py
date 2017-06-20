import asyncio
import re
import shlex

from tanner import config
from tanner.utils import docker_helper
from tanner.utils import patterns


class LfiEmulator:
    def __init__(self, root_path):
        self.helper = docker_helper.DockerHelper()

    async def get_lfi_result(self, container, file_path):
        cmd = 'cat {file}'.format(file= shlex.quote(file_path))
        execute_result = await self.helper.execute_cmd(container, cmd)
        return execute_result

    async def setup_virtual_env(self):
        container_name = 'lfi_container'
        container = await self.helper.create_container(container_name)
        return container

    def scan(self, value):
        detection = None
        if patterns.LFI_ATTACK.match(value):
            detection = dict(name= 'lfi', order= 2)
        return detection

    async def handle(self, attack_params, session=None):
        container = await self.setup_virtual_env()
        result = await self.get_lfi_result(container, attack_params[0]['value'])
        return result
