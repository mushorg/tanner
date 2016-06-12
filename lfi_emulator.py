import os
import re


class LfiEmulator:
    def __init__(self, root_path):
        self.root_path = root_path
        self.whitelist = []

    def available_files(self):
        for root, dirs, files in os.walk(os.path.join(self.root_path, 'data/virtualdocs/')):
            for f in files:
                self.whitelist.append(os.path.join(root, f))

    def lfi_result(self, file):
        result = None
        for f in self.whitelist:
            if re.match('.*' + file, f):
                with open(f) as lfile:
                    result = lfile.read()
        return result

    def handle(self, path):
        self.available_files()
        patt = re.compile('.*=((\.\.|\/).*)')
        file = re.match(patt, path).group(1)
        file = os.path.normpath(os.path.join('/', file))
        return self.lfi_result(file)
