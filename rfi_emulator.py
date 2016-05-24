import json
import urllib.request
import re
import hashlib

class RfiEmulator():
    def __init__(self, path):
        self.path = path

    def download_file(self):

        url_pattern = re.compile('.*=(.*(http(s){0,1}|ftp(s){0,1}):.*)')
        url = url_pattern.match(self.path).group(1)

        if not url.startswith("http"):
            return None

        filename = hashlib.md5(url.encode('utf-8')).hexdigest()

        try:
            urllib.request.urlretrieve(url, filename)
            return filename

        except urllib.request.URLError as e:
            print("downoad failed: ", e.reason)

    def execute_rfi(self):
        # here phpox should start to execute file ?
        pass

    def hadle_rfi(self):
        result = self.download_file()
        print(result)