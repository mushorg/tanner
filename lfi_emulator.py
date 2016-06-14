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
