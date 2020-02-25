import logging

import aioredis

from tanner.session import Session
from tanner.session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self, loop=None):
        self.sessions = []
        self.analyzer = SessionAnalyzer(loop=loop)
        self.logger = logging.getLogger(__name__)

    async def add_or_update_session(self, raw_data, redis_client):
        # prepare the list of sessions
        await self.delete_old_sessions(redis_client)
        # handle raw data
        valid_data = self.validate_data(raw_data)
        # push snare uuid into redis.
        await redis_client.sadd('snare_ids', *[valid_data['uuid']])
        session = self.get_session(valid_data)
        if session is None:
            try:
                new_session = Session(valid_data)
            except KeyError as key_error:
                self.logger.exception('Error during session creation: %s', key_error)
                return
            self.sessions.append(new_session)
            return new_session
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
        if 'cookies' not in data:
            data['cookies'] = dict(sess_uuid=None)
        if 'cookies' in data and 'sess_uuid' not in data['cookies']:
            data['cookies']['sess_uuid'] = None

        return data

    def get_session(self, data):
        session = None
        ip = data['peer']['ip']
        user_agent = data['headers']['user-agent']
        sess_uuid = data['cookies']['sess_uuid']
        for sess in self.sessions:
            if sess.ip == ip and sess.user_agent == user_agent and sess_uuid == sess.get_uuid():
                session = sess
                break
        return session

    async def delete_old_sessions(self, redis_client):
        for sess in self.sessions:
            if not sess.is_expired():
                continue
            else:
                try:
                    self.sessions.remove(sess)
                except Exception:
                    continue

    async def delete_sessions_on_shutdown(self, redis_client):
        for sess in self.sessions:
            is_deleted = await self.delete_session(sess, redis_client)
            if is_deleted:
                self.sessions.remove(sess)

    async def delete_session(self, sess, redis_client):
        await sess.remove_associated_db()
        if sess.associated_env is not None:
            await sess.remove_associated_env()
        try:
            await redis_client.set(sess.get_uuid(), sess.to_json())
            await self.analyzer.analyze(sess.get_uuid(), redis_client)
        except aioredis.ProtocolError as redis_error:
            self.logger.exception('Error connect to redis, session stay in memory. %s', redis_error)
            return False
        else:
            return True
