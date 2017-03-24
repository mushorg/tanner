import asyncio
import re
import urllib.parse
import yarl

from tanner.emulators import lfi, rfi, sqli, xss
from tanner.utils import patterns


class BaseHandler:
    # Reference patterns
    patterns = {
        patterns.RFI_ATTACK: dict(name='rfi', order=2),
        patterns.LFI_ATTACK: dict(name='lfi', order=2),
        patterns.XSS_ATTACK: dict(name='xss', order=3)
    }

    def __init__(self, loop=None):
        base_dir = TannerConfig.get('EMULATORS', 'root_dir')
        db_name = TannerConfig.get('SQLI', 'db_name')
        self.emulators = {
            'rfi': rfi.RfiEmulator(base_dir, loop),
            'lfi': lfi.LfiEmulator(base_dir),
            'xss': xss.XssEmulator(),
            'sqli': sqli.SqliEmulator(db_name, base_dir)
        }

    @asyncio.coroutine
    def handle_post(self, session, data):
        detection = dict(name='unknown', order=0)
        xss_result = yield from self.emulators['xss'].handle(None, session, data)
        if xss_result:
            detection = {'name': 'xss', 'order': 2, 'payload': xss_result}
        else:
            sqli_data = self.emulators['sqli'].check_post_data(data)
            if sqli_data:
                sqli_result = yield from self.emulators['sqli'].handle(sqli_data, session, 1)
                detection = {'name': 'sqli', 'order': 2, 'payload': sqli_result}
        return detection

    @asyncio.coroutine
    def handle_get(self, session, path):
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
            sqli = self.emulators['sqli'].check_get_data(path)
            if sqli:
                detection = {'name': 'sqli', 'order': 2}
                attack_value = path

        if detection['name'] in self.emulators:
            emulation_result = yield from self.emulators[detection['name']].handle(attack_value, session)
            detection['payload'] = emulation_result

        return detection

    @asyncio.coroutine
    def emulate(self, data, session, path):
        if data['method'] == 'POST':
            detection = yield from self.handle_post(session, data)
        else:
            detection = yield from self.handle_get(session, path)

        return detection

    @asyncio.coroutine
    def handle(self, data, session, path):
        detection = yield from self.emulate(data, session, path)
        return detection
