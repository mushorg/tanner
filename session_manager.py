import asyncio
import redis

from session import Session
from session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self):
        self.sessions = []
        self.r = redis.StrictRedis(host='localhost', port=6379)
        self.analyzer = SessionAnalyzer()

    @asyncio.coroutine
    def add_or_update_session(self, raw_data):
        # prepare the list of sessions
        yield from self.delete_old_sessions()
        # handle raw data
        valid_data = self.validate_data(raw_data)
        session = self.get_session(valid_data)
        if session is None:
            try:
                new_session = Session(valid_data)
            except KeyError:
                print('Bad session')
                return
            self.sessions.append(new_session)
            return new_session
        else:
            session.update_session(valid_data)
            return session

    def validate_data(self, data):
        if 'peer' not in data:
            peer = dict(ip=None, port=None)
            data['peer'] = peer

        data['headers'] = dict((k.lower(), v) for k, v in data['headers'].items())
        if 'user-agent' not in data['headers']:
            data['headers']['user-agent'] = None
        if 'path' not in data:
            data['path'] = None
        if 'uuid' not in data:
            data['uuid'] = None
        if 'status' not in data:
            data['status'] = 200 if 'error' not in data else 500
        return data

    def get_session(self, data):
        session = None
        ip = data['peer']['ip']
        user_agent = data['headers']['user-agent']
        for sess in self.sessions:
            if sess.ip == ip and sess.user_agent == user_agent:
                session = sess
                break
        return session

    @asyncio.coroutine
    def delete_old_sessions(self):
        for sess in self.sessions:
            if not sess.is_expired():
                continue
            self.sessions.remove(sess)
            try:
                self.r.set(sess.get_key(), sess.to_json())
                yield from self.analyzer.analyze(sess.get_key())
            except redis.ConnectionError as e:
                self.sessions.append(sess)
