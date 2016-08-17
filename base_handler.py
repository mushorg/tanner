import re
import patterns
import urllib.parse
import asyncio
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
            'sqli': sqli_emulator.SqliEmulator('words.db', '/opt/tanner/db/')
        }

    @asyncio.coroutine
    def handle_post(self, session, data):
        detection = dict(name='unknown', order=0)
        xss_result = yield from self.emulators['xss'].handle(None, session, data)
        if xss_result:
            detection = {'name': 'xss', 'order': 2, 'payload': xss_result}
        else:
            sqli_data = yield from self.emulators['sqli'].check_post_data(data)
            if sqli_data:
                sqli_result = yield from self.emulators['sqli'].handle(sqli_data, session, 1)
                detection = {'name': 'sqli', 'order': 2, 'payload': sqli_result}
        return detection

    @asyncio.coroutine
    def handle_get(self, path):
        detection = dict(name='unknown', order=0)
        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {'name': 'wp-content', 'order': 1}

        path = urllib.parse.unquote(path)
        for pattern, patter_details in self.patterns.items():
            if pattern.match(path):
                if detection['order'] < patter_details['order']:
                    detection = patter_details

        if detection['order'] <= 1:
            sqli = yield from self.emulators['sqli'].check_get_data(path)
            if sqli:
                detection = {'name': 'sqli', 'order': 2}

        return detection

    @asyncio.coroutine
    def emulate(self, data, session, path):
        if data['method'] == 'POST':
            detection = yield from self.handle_post(session, data)
        else:
            detection = yield from self.handle_get(path)
            name = detection['name']
            if name in self.emulators:
                emulator = self.emulators[name]
                emulation_result = yield from emulator.handle(path, session)
                detection['payload'] = emulation_result
        return detection

    @asyncio.coroutine
    def handle(self, data, session, path):
        detection = yield from self.emulate(data, session, path)
        return detection
