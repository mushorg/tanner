from tanner.utils import aiodocker_helper
from tanner.utils import patterns


class CmdExecEmulator:
    def __init__(self):
        self.helper = aiodocker_helper.AIODockerHelper()

    async def get_cmd_exec_results(self, payload):
        cmd = ["sh", "-c", payload]

        execute_result = await self.helper.execute_cmd(cmd)
        result = dict(value=execute_result, page=True)
        return result

    def scan(self, value):
        detection = None
        if patterns.CMD_ATTACK.match(value):
            detection = dict(name="cmd_exec", order=3)
        return detection

    async def handle(self, attack_params, session=None):

        result = await self.get_cmd_exec_results(attack_params[0]["value"])
        return result
