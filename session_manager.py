import asyncio
from session import Session


class SessionManager():
    def __init__(self):
        self.sessions = []

    @asyncio.coroutine
    def add_or_update_session(self, data):
        # check if exist
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
