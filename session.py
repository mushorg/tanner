import json
import time
import os
import uuid


class Session:
    KEEP_ALIVE_TIME = 75

    def __init__(self, data):
        try:
            self.ip = data['peer']['ip']
            self.port = data['peer']['port']
            self.user_agent = data['headers']['user-agent']
            self.sensor = data['uuid']
            self.paths = [{'path': data['path'], 'timestamp': time.time(),
                           'response_status': data['status']}]
            self.associated_db = None
        except KeyError:
            raise

        self.uuid = uuid.uuid4()
        self.start_timestamp = time.time()
        self.timestamp = time.time()
        self.count = 1

    def update_session(self, data):
        self.timestamp = time.time()
        self.count += 1
        self.paths.append({'path': data['path'], 'timestamp': time.time(),
                           'response_status': data['status']})

    def is_expired(self):
        exp_time = self.timestamp + self.KEEP_ALIVE_TIME
        if time.time() - exp_time > 0:
            return True

    def to_json(self):
        sess = dict(peer=dict(ip=self.ip, port=self.port),
                    user_agent=self.user_agent,
                    sensor=self.sensor,
                    uuid=self.uuid.hex,
                    start_time=self.start_timestamp,
                    end_time=self.timestamp,
                    count=self.count,
                    paths=self.paths
                   )
        return json.dumps(sess)

    def set_attack_type(self, path, attack_type):
        for sess_path in self.paths:
            if sess_path == path:
                sess_path.update({'attack_type': attack_type})

    def associate_db(self, db_name):
        self.associated_db = db_name

    def remove_associated_db(self):
        if self.associated_db is not None and os.path.exists(self.associated_db):
            os.remove(self.associated_db)

    def get_key(self):
        return str(self.uuid)
