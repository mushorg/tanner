import logging
import hashlib

import aioredis

from tanner.sessions.session import Session
from tanner.sessions.session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self, loop=None):
        self.sessions = {}
        self.analyzer = SessionAnalyzer(loop=loop)
        self.logger = logging.getLogger(__name__)

    async def add_or_update_session(self, raw_data, redis_client):

        # handle raw data
        valid_data = self.validate_data(raw_data)
        # push snare uuid into redis.
        await redis_client.sadd("snare_ids", *[valid_data["uuid"]])
        session_id = self.get_session_id(valid_data)
        if session_id not in self.sessions:
            try:
                new_session = Session(valid_data)
            except KeyError as key_error:
                self.logger.exception("Error during session creation: %s", key_error)
                return
            self.sessions[session_id] = new_session
            return new_session, session_id
        else:
            self.sessions[session_id].update_session(valid_data)
        # prepare the list of sessions
        return self.sessions[session_id], session_id

    @staticmethod
    def validate_data(data):
        if "peer" not in data:
            peer = dict(ip=None, port=None)
            data["peer"] = peer

        data["headers"] = dict((k.lower(), v) for k, v in data["headers"].items())
        if "user-agent" not in data["headers"]:
            data["headers"]["user-agent"] = None
        if "path" not in data:
            data["path"] = None
        if "uuid" not in data:
            data["uuid"] = None
        if "status" not in data:
            data["status"] = 200 if "error" not in data else 500
        if "cookies" not in data:
            data["cookies"] = dict(sess_uuid=None)
        if "cookies" in data and "sess_uuid" not in data["cookies"]:
            data["cookies"]["sess_uuid"] = None

        return data

    def get_session_id(self, data):
        ip = data["peer"]["ip"]
        user_agent = data["headers"]["user-agent"]
        sess_uuid = data["cookies"]["sess_uuid"]

        sess_id_string = "{ip}{user_agent}{sess_uuid}".format(ip=ip, user_agent=user_agent, sess_uuid=sess_uuid)

        return hashlib.md5(sess_id_string.encode()).hexdigest()

    async def delete_old_sessions(self, redis_client):
        id_for_deletion = [sess_id for sess_id, sess in self.sessions.items() if sess.is_expired()]
        for sess_id in id_for_deletion:
            is_deleted = await self.delete_session(self.sessions[sess_id], redis_client)
            if is_deleted:
                try:
                    del self.sessions[sess_id]
                except ValueError:
                    continue

    async def delete_sessions_on_shutdown(self, redis_client):
        id_for_deletion = list(self.sessions.keys())

        for sess_id in id_for_deletion:
            is_deleted = await self.delete_session(self.sessions[sess_id], redis_client)
            if is_deleted:
                del self.sessions[sess_id]

        try:
            assert len(self.sessions) == 0
        except AssertionError:
            self.logger.exception("Not all sessions were moved to the storage!")

    async def delete_session(self, sess, redis_client):
        await sess.remove_associated_db()
        if sess.associated_env is not None:
            await sess.remove_associated_env()
        try:
            await redis_client.set(sess.get_uuid(), sess.to_json())
            await self.analyzer.analyze(sess.get_uuid(), redis_client)
        except aioredis.ConnectionError as redis_error:
            self.logger.exception("Error connect to redis, session stay in memory. %s", redis_error)
            return False
        else:
            return True
