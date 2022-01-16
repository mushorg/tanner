import traceback
import json
from datetime import datetime

import tanner.reporting.hpfeeds as hpfeeds

from tanner import config


class Reporting:
    def __init__(self):
        # Create the connection
        self.host = config.TannerConfig.get("HPFEEDS", "HOST")
        self.port = config.TannerConfig.get("HPFEEDS", "PORT")
        self.ident = config.TannerConfig.get("HPFEEDS", "IDENT")
        self.secret = config.TannerConfig.get("HPFEEDS", "SECRET")
        self.channel = config.TannerConfig.get("HPFEEDS", "CHANNEL")
        self.reconnect = True

    def connect(self):
        try:
            self.hpc = hpfeeds.new(self.host, self.port, self.ident, self.secret, self.reconnect)
            self.connected_state = True
        except Exception:
            self.connected_state = False

    def connected(self):
        return self.connected_state

    def create_session(self, session_data):
        session_data["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
        event_data = json.dumps(session_data)
        try:
            self.hpc.publish(self.channel, event_data)
        except Exception:
            self.connected_state = False
            traceback.print_exc()
