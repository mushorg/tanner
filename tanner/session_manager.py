import asyncio
import logging

import asyncio_redis

from tanner.session import Session
from tanner.session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self):
        self.sessions = []
        self.analyzer = SessionAnalyzer()
        self.logger = logging.getLogger('tanner.session_manager.SessionManager')

    @asyncio.coroutine
    def add_or_update_session(self, raw_data, redis_client):
        # prepare the list of sessions
        yield from self.delete_old_sessions(redis_client)
        # handle raw data
        valid_data = self.validate_data(raw_data)
        # push snare uuid into redis.
        yield from redis_client.sadd('snare_ids', [valid_data['uuid']])
        session = self.get_session(valid_data)
        if session is None:
            try:
                new_session = Session(valid_data)
            except KeyError as key_error:
                self.logger.error('Error during session creation: %s', key_error)
                return
            self.sessions.append(new_session)
            return new_session
        else:
            session.update_session(valid_data)
            return session

    @staticmethod
    def validate_data(data):
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
    def delete_old_sessions(self, redis_client):
        for sess in self.sessions:
            if not sess.is_expired():
                continue
            sess.remove_associated_db()
            self.sessions.remove(sess)
            try:
                yield from redis_client.set(sess.get_key(), sess.to_json())
                yield from self.analyzer.analyze(sess.get_key(), redis_client)
            except asyncio_redis.NotConnectedError as redis_error:
                self.logger.error('Error connect to redis, session stay in memory. %s', redis_error)
                self.sessions.append(sess)
