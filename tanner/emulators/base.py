import asyncio
import re
import urllib.parse
import yarl

from tanner.emulators import lfi, rfi, sqli, xss, cmd_exec
from tanner.utils import patterns


class BaseHandler:
    # Reference patterns
    patterns = {
        patterns.RFI_ATTACK: dict(name='rfi', order=2),
        patterns.LFI_ATTACK: dict(name='lfi', order=2),
        patterns.XSS_ATTACK: dict(name='xss', order=3)
    }

    def __init__(self, base_dir, db_name, loop=None):
        self.emulators = {
            'rfi': rfi.RfiEmulator(base_dir, loop),
            'lfi': lfi.LfiEmulator(base_dir),
            'xss': xss.XssEmulator(),
            'sqli': sqli.SqliEmulator(db_name, base_dir),
            'cmd_exec': cmd_exec.CmdExecEmulator()
        }

    async def handle_post(self, session, data):
        detection = dict(name='unknown', order=0)
        xss_result = await self.emulators['xss'].handle(None, session, data)
        if xss_result:
            detection = {'name': 'xss', 'order': 2, 'payload': xss_result}
        else:
            sqli_data = self.emulators['sqli'].check_post_data(data)
            if sqli_data:
                sqli_result = await self.emulators['sqli'].handle(sqli_data, session, 1)
                detection = {'name': 'sqli', 'order': 2, 'payload': sqli_result}
            else:
                cmd_exec_data = await self.emulators['cmd_exec'].check_post_data(data)
                if cmd_exec_data:
                    cmd_exec_results = await self.emulators['cmd_exec'].handle(cmd_exec_data[0][1], session)
                    detection = {'name': 'cmd_exec', 'order': 3, 'payload': cmd_exec_results}

        return detection

    async def handle_get(self, session, path):
        detection = dict(name='unknown', order=0)
        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {'name': 'wp-content', 'order': 1}
        if re.match(patterns.INDEX, path):
            detection = {'name': 'index', 'order': 1}

        path = urllib.parse.unquote(path)
        query = yarl.URL(path).query

        for name, value in query.items():
            for pattern, patter_details in self.patterns.items():
                if pattern.match(value):
                    if detection['order'] < patter_details['order']:
                        detection = patter_details
                        attack_value = value

        if detection['order'] <= 1:
            cmd_exec = await self.emulators['cmd_exec'].check_get_data(path)
            if cmd_exec:
                detection = {'name': 'cmd_exec', 'order': 3}
                attack_value = cmd_exec[0][1]
            else:
                sqli = self.emulators['sqli'].check_get_data(path)
                if sqli:
                    detection = {'name': 'sqli', 'order': 2}
                    attack_value = path

        if detection['name'] in self.emulators:
            emulation_result = await self.emulators[detection['name']].handle(attack_value, session)
            detection['payload'] = emulation_result

        return detection

    async def emulate(self, data, session, path):
        if data['method'] == 'POST':
            detection = await self.handle_post(session, data)
        else:
            detection = await self.handle_get(session, path)

        return detection

    async def handle(self, data, session, path):
        detection = await self.emulate(data, session, path)
        return detection
