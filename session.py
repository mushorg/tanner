import time


class Session:

    KEEP_ALIVE_TIME = 75

    def __init__(self, data):
        self.ip = data['peer']['ip']
        self.port = data['peer']['port']
        self.user_agent = data['headers']['USER-AGENT']
        self.uuid = data['uuid']
        self.timestamp = time.time()
        self.count = 1

    def update_session(self):
        self.timestamp = time.time()
        self.count += 1

    def expiried(self):
        exp_time = self.timestamp + self.KEEP_ALIVE_TIME
        if (time.time() - exp_time > 0):
            return True
