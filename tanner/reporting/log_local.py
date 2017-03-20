import json
import os

from tanner import config


class Reporting():
    def __init__(self):
        self.report_file = config.TannerConfig.get('LOCALLOG', 'PATH')
        if not os.path.exists(self.report_file):
            with open(self.report_file, 'w') as out:
                json.dump([], out)

    def create_session(self, session_data):
        with open(self.report_file, 'br+') as out:
            out.seek(-1, 2)
            out.truncate()

        with open(self.report_file, 'a') as out:
            if os.path.getsize(self.report_file) != 1:
                out.write(",")
            json.dump(session_data, out)
            out.write("]")
