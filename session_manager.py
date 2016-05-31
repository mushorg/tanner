import asyncio
from session import Session


class SessionManager():
    def __init__(self):
        self.sessions = []

    @asyncio.coroutine
    def add_or_update_session(self, data):
        #prepare the list of sessions
        self.delete_old_sessions()

        new_session = Session(data)
        session = self.get_session(new_session)
        if session is None:
            self.sessions.append(new_session)
        else:
            session.update_session()

        print('==========EXISTING SESSIONS============')
        for s in self.sessions:
            print("Session with ip", s.ip)
        print('=======================================')

    def get_session(self, session):
        if len(self.sessions) == 0:
            return None

        for sess in self.sessions:
            if sess.ip == session.ip:
                return sess

    def delete_old_sessions(self):
        for sess in self.sessions:
            if not sess.expiried():
                continue
            self.sessions.remove(sess)