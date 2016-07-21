import re
import patterns
import urllib.parse
import asyncio
from asyncio.subprocess import PIPE
import rfi_emulator
import xss_emulator
import lfi_emulator


class BaseHandler:
    # Reference patterns
    patterns = {
        patterns.INDEX: dict(name='index', order=1),
        patterns.RFI_ATTACK: dict(name='rfi', order=2),
        patterns.LFI_ATTACK: dict(name='lfi', order=2),
        patterns.XSS_ATTACK: dict(name='xss', order=3)
    }

    def __init__(self):
        self.rfi_emulator = rfi_emulator.RfiEmulator('/opt/tanner/')
        self.xss_emulator = xss_emulator.XssEmulator()
        self.lfi_emulator = lfi_emulator.LfiEmulator('/opt/tanner/')

    def check_sqli(self, path):
        @asyncio.coroutine
        def _run_cmd(cmd):
            proc = yield from asyncio.wait_for(asyncio.create_subprocess_exec(*cmd, stdout=PIPE), 5)
            line = yield from asyncio.wait_for(proc.stdout.readline(), 10)
            return line

        command = ['/usr/bin/python2', 'sqli_check.py', path]
        res = yield from _run_cmd(command)
        return res

    @asyncio.coroutine
    def detect_attack(self, data, session, path):
        if data['method'] == 'POST':
            xss_result = self.xss_emulator.handle(session, None, data)
            if xss_result:
                detection = {'name': 'xss', 'order': 2, 'payload': xss_result}

        detection = dict(name='unknown', order=0)
        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {'name': 'wp-content', 'order': 1}

        elif self.check_sqli(path):
            detection = {'name': 'sqli', 'order': 2}
        else:
            path = urllib.parse.unquote(path)
            for pattern, patter_details in self.patterns.items():
                if pattern.match(path):
                    if detection['order'] < patter_details['order']:
                        detection = patter_details
        return detection

    @asyncio.coroutine
    def emulate(self, detection, session, path):
        if detection['name'] == 'rfi':
            rfi_emulation_result = yield from self.rfi_emulator.handle_rfi(path)
            detection['payload'] = rfi_emulation_result
        elif detection['name'] == 'xss':
            xss_result = self.xss_emulator.handle(session, path)
            detection['payload'] = xss_result
        elif detection['name'] == 'lfi':
            lfi_result = self.lfi_emulator.handle(path)
            detection['payload'] = lfi_result

    @asyncio.coroutine
    def handle(self, data, session, path):
        detection = yield from self.detect_attack(data, session, path)
        yield from self.emulate(detection, session, path)
        return detection
