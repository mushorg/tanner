import os
import re
import json
import patterns
import asyncio


class LfiEmulator:
    def __init__(self, root_path):
        self.vdoc_path = root_path + '/virtualdocs/'
        self.whitelist = []
        self.setup_vdocs()

    @asyncio.coroutine
    def available_files(self):
        for root, dirs, files in os.walk(self.vdoc_path):
            for f in files:
                self.whitelist.append(os.path.join(root, f))

    @asyncio.coroutine
    def get_lfi_result(self, file_path):
        result = None
        for f in self.whitelist:
            if file_path in f:
                with open(f) as lfile:
                    result = lfile.read()
                lfile.close()
        return result

    @asyncio.coroutine
    def get_file_path(self, path):
        file_path = re.match(patterns.LFI_FILEPATH, path).group(1)
        file_path = os.path.normpath(os.path.join('/', file_path))
        return file_path

    def setup_vdocs(self):
        vdocs = None
        if not os.path.exists(self.vdoc_path + 'linux/'):
            os.makedirs(self.vdoc_path + 'linux/')
        for root, dirs, files in os.walk(self.vdoc_path + 'linux/'):
            if not files:
                with open('data/vdocs.json') as vdf:
                    vdocs = json.load(vdf)
                vdf.close()
        if vdocs:
            for k, v in vdocs.items():
                filename = self.vdoc_path + 'linux/' + k
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w') as vd:
                    vd.write(v)
                vd.close()

    @asyncio.coroutine
    def handle(self, path, session=None):
        if not self.whitelist:
            yield from self.available_files()
        file_path = yield from self.get_file_path(path)
        result = yield from self.get_lfi_result(file_path)
        return result
