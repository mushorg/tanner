import asyncio
from session import Session


class SessionManager:
    def __init__(self):
        self.sessions = []

    @asyncio.coroutine
    def add_or_update_session(self, data):
        # prepare the list of sessions
        self.delete_old_sessions()
        if 'peer' not in data:
            peer = dict(ip=None, port=None)
            data['peer'] = peer
        session = self.get_session(data)
        if session is None:
            new_session = Session(data)
            self.sessions.append(new_session)
        else:
            session.update_session()

    def get_session(self, data):
        session = None
        ip = data['peer']['ip']
        user_agent = data['headers']['USER-AGENT']
        for sess in self.sessions:
            if sess.ip == ip and sess.user_agent == user_agent:
                session = sess
                break
        return session

    def delete_old_sessions(self):
        for sess in self.sessions:
            if not sess.is_expired():
                continue
            self.sessions.remove(sess)
