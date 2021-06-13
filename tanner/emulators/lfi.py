import shlex

from tanner.utils import aiodocker_helper
from tanner.utils import patterns


class LfiEmulator:
    def __init__(self):
        self.helper = aiodocker_helper.AIODockerHelper()

    async def get_lfi_result(self, file_path):
        # Terminate the string with NULL byte
        if "\x00" in file_path:
            file_path = file_path[: file_path.find("\x00")]

        cmd = ["sh", "-c", "cat {file}".format(file=shlex.quote(file_path))]
        execute_result = await self.helper.execute_cmd(cmd)

        if execute_result:
            # Nulls are not printable, so replace it with another line-ender
            execute_result = execute_result.replace("\x00", "\n")
        return execute_result

    def scan(self, value):
        detection = None
        if patterns.LFI_ATTACK.match(value):
            detection = dict(name="lfi", order=2)
        return detection

    async def handle(self, attack_params, session=None):

        lfi_result = await self.get_lfi_result(attack_params[0]["value"])
        result = dict(value=lfi_result, page=False)
        return result
