import asyncio
import json
import os
import re

from tanner import config
from tanner.utils import patterns


class LfiEmulator:
    def __init__(self, root_path):
        self.vdoc_path = os.path.join(root_path, 'virtualdocs/linux')
        self.whitelist = []
        self.setup_or_update_vdocs()

    def available_files(self):
        for root, dirs, files in os.walk(self.vdoc_path):
            for filename in files:
                self.whitelist.append(os.path.join(root, filename))

    def get_lfi_result(self, file_path):
        result = None
        if file_path in self.whitelist:
            with open(file_path) as lfile:
                result = lfile.read()
        return result

    def get_file_path(self, path):
        file_match = re.match(patterns.LFI_FILEPATH, path)
        if file_match:
            file_path_relative = file_match.group(1)
            file_path_relative = os.path.normpath(os.path.join('/', file_path_relative))
            file_path = os.path.join(self.vdoc_path, file_path_relative[1:])
        else:
            file_path = path
        return file_path

    def setup_or_update_vdocs(self):
        if not os.path.exists(self.vdoc_path):
            os.makedirs(self.vdoc_path)

        with open(config.TannerConfig.get('DATA', 'vdocs')) as vdf:
            vdocs = json.load(vdf)

        if vdocs:
            for key, value in vdocs.items():
                filename = os.path.join(self.vdoc_path, key)
                if not os.path.exists(filename):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
                    with open(filename, 'w') as vd:
                        vd.write(value)

    def scan(self, value):
        detection = None
        if patterns.LFI_ATTACK.match(value):
            detection = dict(name= 'lfi', order= 2)
        return detection

    async def handle(self, attack_value, session=None):
        if not self.whitelist:
            self.available_files()
        file_path = self.get_file_path(attack_value['value'])
        result = self.get_lfi_result(file_path)
        return result
