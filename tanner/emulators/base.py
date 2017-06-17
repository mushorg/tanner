import asyncio
import re
import urllib.parse
import yarl

from tanner.emulators import lfi, rfi, sqli, xss, cmd_exec
from tanner.utils import patterns

class BaseHandler:
    def __init__(self, base_dir, db_name, loop=None):
        self.emulators = {
            'rfi': rfi.RfiEmulator(base_dir, loop),
            'lfi': lfi.LfiEmulator(base_dir),
            'xss': xss.XssEmulator(),
            'sqli': sqli.SqliEmulator(db_name, base_dir),
            'cmd_exec': cmd_exec.CmdExecEmulator()
        }
        self.get_emulators = ['sqli', 'rfi', 'lfi', 'xss', 'cmd_exec']
        self.post_emulators = ['sqli', 'rfi', 'lfi', 'xss', 'cmd_exec']
        self.cookie_emulators = ['sqli']

    def extract_get_data(self, path):
        """
        Return all the GET parameter
        :param path (str): The URL path from which GET parameters are to be extracted
        :return: A MultiDictProxy object containg name and value of parameters
        """
        path = urllib.parse.unquote(path)
        encodings = [('&&', '%26%26'), (';', '%3B')] 
        for value, encoded_value in encodings:
            path = path.replace(value, encoded_value)
        get_data = yarl.URL(path).query
        return get_data

    async def get_emulation_result(self, session, data, target_emulators):
        """
        Return emulation result for the vulnerabilty of highest order
        :param session (Session object): Current active session
        :param data (MultiDictProxy object): Data to be checked
        :param target_emulator (list): Emulators against which data is to be checked
        :return: A dict object containing name, order and paylod to be injected for vulnerability  
        """
        detection = dict(name='unknown', order=0)
        attack_params = {}
        for param_id, param_value in data.items():
            for emulator in target_emulators:
                possible_detection = self.emulators[emulator].scan(param_value) if param_value else None
                if possible_detection:
                    if detection['order'] < possible_detection['order']:
                        detection = possible_detection
                    if emulator not in attack_params:
                        attack_params[emulator] = []
                    attack_params[emulator].append(dict(id= param_id, value= param_value))
                    
        if detection['name'] in self.emulators:
            emulation_result = await self.emulators[detection['name']].handle(attack_params[detection['name']], session)
            detection['payload'] = emulation_result

        return detection

    async def handle_post(self, session, data):
        post_data = data['post_data']

        detection = await self.get_emulation_result(session, post_data, self.post_emulators)
        return detection

    async def handle_cookies(self, session, data):
        cookies = data['cookies']

        detection = await self.get_emulation_result(session, cookies, self.cookie_emulators)
        return detection

    async def handle_get(self, session, data):
        path = data['path']
        get_data = self.extract_get_data(path)
        detection = dict(name='unknown', order=0)
        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {'name': 'wp-content', 'order': 1}
        if re.match(patterns.INDEX, path):
            detection = {'name': 'index', 'order': 1}
        # check attacks against get parameters
        possible_get_detection = await self.get_emulation_result(session, get_data, self.get_emulators)
        if possible_get_detection and detection['order'] < possible_get_detection['order'] :
            detection = possible_get_detection
        # check attacks against cookie values
        possible_cookie_detection = await self.handle_cookies(session, data)
        if possible_cookie_detection and detection['order'] < possible_cookie_detection['order'] :
            detection = possible_cookie_detection

        return detection

    async def emulate(self, data, session):
        if data['method'] == 'POST':
            detection = await self.handle_post(session, data)
        else:
            detection = await self.handle_get(session, data)

        return detection

    async def handle(self, data, session):
        detection = await self.emulate(data, session)
        return detection