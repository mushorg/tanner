import logging
import hashlib
import asyncio
import time

import aioredis

from tanner.sessions.session import Session
from tanner.sessions.session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self, loop=None, delete_timeout=60*5):
        self.sessions = {}
        self.analyzer = SessionAnalyzer(loop=loop)
        self.logger = logging.getLogger(__name__)
        self.delete_timeout = delete_timeout

    async def add_or_update_session(self, raw_data, redis_client):

        # handle raw data
        valid_data = self.validate_data(raw_data)
        # push snare uuid into redis.
        await redis_client.sadd('snare_ids', *[valid_data['uuid']])
        session_uuid = self.get_session_uuid(valid_data)
        if session_uuid not in self.sessions:
            try:
                new_session = Session(valid_data)
            except KeyError as key_error:
                self.logger.exception('Error during session creation: %s', key_error)
                return
            self.sessions[session_uuid] = new_session
            return new_session
        else:
            self.sessions[session_uuid].update_session(valid_data)
        # prepare the list of sessions
        return self.sessions[session_uuid]

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

    def get_session_uuid(self, data):
        ip = data['peer']['ip']
        user_agent = data['headers']['user-agent'] if data['headers']['user-agent'] is not None else "" 
        sess_uuid = data['cookies']['sess_uuid'] if data['cookies']['sess_uuid'] is not None else ""

        return hashlib.md5((ip+user_agent+sess_uuid).encode()).hexdigest()

    async def delete_old_sessions(self, redis_client):

        while True:
            for sess_uuid, session in self.sessions.items():
                if not session.is_expired():
                    continue
                is_deleted = await self.delete_session(session, redis_client)
                if is_deleted:
                    try:
                        del self.sessions[sess_uuid]
                    except ValueError:
                        continue
            await asyncio.sleep(self.delete_timeout)

    async def delete_sessions_on_shutdown(self, redis_client):
        for sess_uuid, sess in self.sessions.items():
            is_deleted = await self.delete_session(sess, redis_client)
            if is_deleted:
                del self.sessions[sess_uuid]

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
