import time


class Session():
    def __init__(self, data):
        self.ip = data['peer'][0]
        self.port = data['peer'][1]
        self.user_agent = data['headers']['USER-AGENT']
        self.uuid = data['uuid']
        self.timestamp = time.time()
        self.keep_alive = 75

    def update_session(self):
        self.timestamp = time.time()

    def expiried(self):
        exp_time = self.timestamp + self.timestamp
        if (time.time() - exp_time > 0):
            return True
