import time
import json
import hashlib


class Session:
    KEEP_ALIVE_TIME = 75

    def __init__(self, data):
        self.ip = data['peer']['ip']
        self.port = data['peer']['port']
        self.user_agent = data['headers']['USER-AGENT']
        self.uuid = data['uuid']
        self.timestamp = time.time()
        self.count = 1
        self.paths = []

    def update_session(self):
        self.timestamp = time.time()
        self.count += 1

    def is_expired(self):
        exp_time = self.timestamp + self.KEEP_ALIVE_TIME
        if (time.time() - exp_time > 0):
            return True

    def to_json(self):
        s = dict(peer=dict(ip=self.ip, port=self.port),
                 user_agent=self.user_agent,
                 uuid=self.uuid,
                 timestamp=self.timestamp,
                 count=self.count,
                 paths=self.paths
                 )
        return json.dumps(s)

    def get_key(self):
        bstr = (self.ip + self.user_agent).encode('utf-8')
        return hashlib.md5(bstr).digest()
