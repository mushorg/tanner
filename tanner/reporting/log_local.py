import os
import json

from tanner import config

class Reporting():
    def __init__(self):
        # check if file exists, else create
        pass

    def create_session(self, session_data):
        report_file = config.TannerConfig.config['LOCALLOG']['PATH']
        with open(report_file, 'a') as out:
            out.write('{0}\n'.format(session_data))
        return '1'
