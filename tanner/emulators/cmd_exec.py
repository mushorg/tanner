import asyncio
import yarl

from tanner.utils import docker_helper
from tanner.utils import patterns

class CmdExecEmulator:
    def __init__(self):
        self.helper = docker_helper.DockerHelper()
    
    async def create_attacker_env(self, session):
        container_name = 'attacker_' + session.sess_uuid.hex
        container = await self.helper.create_container(container_name)
        if container:
            session.associate_env(container_name)
        return container

    async def get_cmd_exec_results(self, container, cmd):
        execute_result = await self.helper.execute_cmd(container, cmd)
        result = dict(value=execute_result, page=True)
        return result

    def scan(self, value):
        detection = None
        if patterns.CMD_ATTACK.match(value):
            detection = dict(name= 'cmd_exec', order= 3)
        return detection

    async def handle(self, attack_params, session= None):
        container = await self.create_attacker_env(session)
        result = await self.get_cmd_exec_results(container, attack_params[0]['value'])
        return result
