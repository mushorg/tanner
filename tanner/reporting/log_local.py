import json
from datetime import datetime
from tanner import config


class Reporting:
    @staticmethod
    def create_session(session_data):
        report_file = config.TannerConfig.get('LOCALLOG', 'PATH')
        with open(report_file, 'a') as out:
            json.dump({datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f'):session_data}, out)
            out.write('\n')
