import traceback
import json

import tanner.reporting.hpfeeds as hpfeeds

from tanner import config

class Reporting():
    def __init__(self):
        # Create the connection
        self.host = config.TannerConfig.get('HPFEEDS', 'HOST')
        self.port = int(config.TannerConfig.get('HPFEEDS', 'PORT'))
        self.ident = config.TannerConfig.get('HPFEEDS', 'IDENT')
        self.secret = config.TannerConfig.get('HPFEEDS', 'SECRET')
        self.channel = config.TannerConfig.get('HPFEEDS', 'CHANNEL')
        self.reconnect=True
            
        self.hpc = hpfeeds.new(self.host, self.port, self.ident, self.secret, self.reconnect)

    def create_session(self, session_data):
        event_data = json.dumps(session_data)
        try:
            self.hpc.publish(self.channel, event_data)
        except:
            traceback.print_exc()
