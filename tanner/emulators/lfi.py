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
        if not os.path.exists(os.path.join(self.vdoc_path, 'vdoc.lock')):
            self.setup_vdocs()

    @asyncio.coroutine
    def available_files(self):
        for root, dirs, files in os.walk(self.vdoc_path):
            for filename in files:
                self.whitelist.append(os.path.join(root, filename))

    @asyncio.coroutine
    def get_lfi_result(self, file_path):
        result = None
        for filename in self.whitelist:
            if file_path in filename:
                with open(filename) as lfile:
                    result = lfile.read()
        return result

    @asyncio.coroutine
    def get_file_path(self, path):
        file_match = re.match(patterns.LFI_FILEPATH, path)
        if file_match:
            file_path_relative = file_match.group(1)
            file_path_relative = os.path.normpath(os.path.join('/', file_path_relative))
            file_path = os.path.join(self.vdoc_path, file_path_relative[1:])
        else:
            file_path = path
        return file_path

    def setup_vdocs(self):
        vdocs = None
        if not os.path.exists(self.vdoc_path):
            os.makedirs(self.vdoc_path)
        for root, dirs, files in os.walk(self.vdoc_path):
            if not files:
                with open(config.TannerConfig.get('DATA', 'vdocs')) as vdf:
                    vdocs = json.load(vdf)
        if vdocs:
            for key, value in vdocs.items():
                filename = os.path.join(self.vdoc_path, key)
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w') as vd:
                    vd.write(value)
            open(os.path.join(self.vdoc_path, 'vdoc.lock'), 'a').close()

    @asyncio.coroutine
    def handle(self, path, session=None):
        if not self.whitelist:
            yield from self.available_files()
        file_path = yield from self.get_file_path(path)
        result = yield from self.get_lfi_result(file_path)
        return result
