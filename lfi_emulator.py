import os
import re
import json


class LfiEmulator:
    def __init__(self, root_path):
        self.vdoc_path = root_path + '/virtualdocs/'
        self.whitelist = []
        self.setup_vdocs()

    def available_files(self):
        for root, dirs, files in os.walk(self.vdoc_path):
            for f in files:
                self.whitelist.append(os.path.join(root, f))

    def lfi_result(self, file_path):
        result = None
        for f in self.whitelist:
            if file_path in f:
                with open(f) as lfile:
                    result = lfile.read()
        return result

    def get_file_path(self, path):
        patt = re.compile('.*=((\.\.|\/).*)')
        file_path = re.match(patt, path).group(1)
        file_path = os.path.normpath(os.path.join('/', file_path))
        return file_path

    def handle(self, path):
        self.available_files()
        file_path = self.get_file_path(path)
        return self.lfi_result(file_path)

    def setup_vdocs(self):
        vdocs = None
        if not os.path.exists(self.vdoc_path + 'linux/'):
            os.makedirs(self.vdoc_path + 'linux/')
        for root, dirs, files in os.walk(self.vdoc_path + 'linux/'):
            if not files:
                with open('data/vdocs.json') as vdf:
                    vdocs = json.load(vdf)
        if vdocs:
            for k, v in vdocs.items():
                filename = self.vdoc_path + 'linux/' + k
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w') as vd:
                    vd.write(v)
