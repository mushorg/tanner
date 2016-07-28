import re
import patterns
import urllib.parse
import asyncio
from asyncio.subprocess import PIPE
import rfi_emulator
import xss_emulator
import lfi_emulator
import sqli_emulator


class BaseHandler:
    # Reference patterns
    patterns = {
        patterns.INDEX: dict(name='index', order=1),
        patterns.RFI_ATTACK: dict(name='rfi', order=2),
        patterns.LFI_ATTACK: dict(name='lfi', order=2),
        patterns.XSS_ATTACK: dict(name='xss', order=3)
    }

    def __init__(self):
        self.emulators = {
            'rfi': rfi_emulator.RfiEmulator('/opt/tanner/'),
            'lfi': lfi_emulator.LfiEmulator('/opt/tanner/'),
            'xss': xss_emulator.XssEmulator(),
            'sqli': sqli_emulator.SqliEmulator('test.db', '/opt/tanner/db/')
        }

    @asyncio.coroutine
    def check_sqli(self, path):
        @asyncio.coroutine
        def _run_cmd(cmd):
            proc = yield from asyncio.wait_for(asyncio.create_subprocess_exec(*cmd, stdout=PIPE), 5)
            line = yield from asyncio.wait_for(proc.stdout.readline(), 10)
            return line

        command = ['/usr/bin/python2', 'sqli_check.py', path]
        res = yield from _run_cmd(command)
        if res is not None:
            try:
                res = int(res.decode('utf-8'))
            except ValueError:
                res = 0
        return res

    @asyncio.coroutine
    def detect_attack(self, data, session, path):
        detection = dict(name='unknown', order=0)
        if data['method'] == 'POST':
            #TODO: check if sqli
            xss_result = yield from self.emulators['xss'].handle(None, session, data)
            if xss_result:
                detection = {'name': 'xss', 'order': 3, 'payload': xss_result}

        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {'name': 'wp-content', 'order': 1}

        query = urllib.parse.urlparse(path).query
        parsed_queries = urllib.parse.parse_qsl(query)
        for q in parsed_queries:
            sqli = yield from self.check_sqli(q[1])
            if sqli:
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
        name = detection['name']
        if name in self.emulators:
            emulator = self.emulators[name]
            emulation_result = yield from emulator.handle(path, session)
            detection['payload'] = emulation_result

    @asyncio.coroutine
    def handle(self, data, session, path):
        detection = yield from self.detect_attack(data, session, path)
        yield from self.emulate(detection, session, path)
        return detection
