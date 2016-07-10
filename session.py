import time
import json
import hashlib
import uuid


class Session:
    KEEP_ALIVE_TIME = 75

    def __init__(self, data):
        try:
            self.ip = data['peer']['ip']
            self.port = data['peer']['port']
            self.user_agent = data['headers']['user-agent']
            self.sensor = data['uuid']
            self.paths = [{'path': data['path'], 'timestamp': time.time(), 'response_status': data['status']}]
        except KeyError:
            raise

        self.uuid = uuid.uuid4()
        self.start_timestamp = time.time()
        self.timestamp = time.time()
        self.count = 1

    def update_session(self, data):
        self.timestamp = time.time()
        self.count += 1
        self.paths.append({'path': data['path'], 'timestamp': time.time(), 'response_status': data['status']})

    def is_expired(self):
        exp_time = self.timestamp + self.KEEP_ALIVE_TIME
        if time.time() - exp_time > 0:
            return True

    def to_json(self):
        s = dict(peer=dict(ip=self.ip, port=self.port),
                 user_agent=self.user_agent,
                 sensor=self.sensor,
                 uuid=self.uuid.hex,
                 start_time=self.start_timestamp,
                 end_time=self.timestamp,
                 count=self.count,
                 paths=self.paths
                 )
        return json.dumps(s)

    def set_attack_type(self, path, attack_type):
        for p in self.paths:
            if p == path:
                p.update({'attack_type': attack_type})

    def get_key(self):
        return self.uuid
