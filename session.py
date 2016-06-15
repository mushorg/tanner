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
        except KeyError as e:
            raise

        self.uuid = uuid.uuid4()
        self.timestamp = time.time()
        self.count = 1

    def update_session(self, path):
        self.timestamp = time.time()
        self.count += 1
        self.paths.append({'path': path, 'timestamp': time.time()})

    def is_expired(self):
        exp_time = self.timestamp + self.KEEP_ALIVE_TIME
        if time.time() - exp_time > 0:
            return True

    def to_json(self):
        s = dict(peer=dict(ip=self.ip, port=self.port),
                 user_agent=self.user_agent,
                 sensor=self.sensor,
                 uuid=self.uuid.hex,
                 timestamp=self.timestamp,
                 count=self.count,
                 paths=self.paths
                 )
        return json.dumps(s)

    def set_attack_type(self, attack_type):
        self.paths[-1].update({'attack_type': attack_type})

    def get_key(self):
        return self.uuid
