import asyncio
import unittest
from unittest import mock
import hashlib

from tanner.sessions import session_manager, session


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = session_manager.SessionManager(loop=self.loop)
        self.handler.analyzer = mock.Mock()
        self.handler.analyzer.send = mock.Mock()

    def test_validate_missing_peer(self):
        data = {
            "headers": {
                "USER-AGENT": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/41.0.2228.0 Safari/537.36"
            },
            "path": "/foo",
            "uuid": None,
            "cookies": {"sess_uuid": None},
        }

        assertion_data = {
            "peer": {"ip": None, "port": None},
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/41.0.2228.0 Safari/537.36"
            },
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_uuid": None},
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_validate_missing_user_agent(self):
        data = {
            "peer": {"ip": "127.0.0.1", "port": 80},
            "headers": {},
            "path": "/foo",
            "uuid": None,
            "cookies": {"sess_uuid": None},
        }

        assertion_data = {
            "peer": {"ip": "127.0.0.1", "port": 80},
            "headers": {"user-agent": None},
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_uuid": None},
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_validate_missing_cookies(self):
        data = {"peer": {"ip": "127.0.0.1", "port": 80}, "headers": {}, "path": "/foo", "uuid": None}

        assertion_data = {
            "peer": {"ip": "127.0.0.1", "port": 80},
            "headers": {"user-agent": None},
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_uuid": None},
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_adding_new_session(self):
        data = {
            "peer": {"ip": None, "port": None},
            "headers": {},
            "path": "/foo",
            "uuid": None,
            "cookies": {"sess_uuid": None},
        }

        async def sess_sadd(key, value):
            return None

        redis_mock = mock.Mock()
        redis_mock.sadd = sess_sadd
        sess, sess_id = self.loop.run_until_complete(self.handler.add_or_update_session(data, redis_mock))

        self.assertDictEqual({sess_id: sess}, self.handler.sessions)

    def test_updating_session(self):
        async def sess_sadd(key, value):
            return None

        data = {
            "peer": {"ip": None, "port": None},
            "headers": {"user-agent": None},
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_uuid": None},
        }
        sess = session.Session(data)

        ip = data["peer"]["ip"]
        user_agent = data["headers"]["user-agent"]
        sess_uuid = data["cookies"]["sess_uuid"]

        sess_id_string = "{ip}{user_agent}{sess_uuid}".format(ip=ip, user_agent=user_agent, sess_uuid=sess_uuid)

        sess_id = hashlib.md5(sess_id_string.encode()).hexdigest()

        redis_mock = mock.Mock()
        redis_mock.sadd = sess_sadd
        self.handler.sessions[sess_id] = sess
        self.loop.run_until_complete(self.handler.add_or_update_session(data, redis_mock))
        self.assertEqual(self.handler.sessions[sess_id].count, 2)

    def test_deleting_sessions(self):
        async def analyze(session_key, redis_client):
            return None

        async def sess_set(key, val):
            return None

        self.handler.analyzer.analyze = analyze
        data = {
            "peer": {"ip": None, "port": None},
            "headers": {"user-agent": None},
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_uuid": None},
        }
        sess = session.Session(data)
        sess.is_expired = mock.MagicMock(name="expired")
        sess.is_expired.__bool__.reurned_value = True
        self.handler.sessions[sess] = sess
        redis_mock = mock.Mock()
        redis_mock.set = sess_set
        self.loop.run_until_complete(self.handler.delete_old_sessions(redis_mock))
        self.assertDictEqual(self.handler.sessions, {})

    def test_get_uuid(self):
        data = {
            "peer": {"ip": None, "port": None},
            "headers": {"user-agent": None},
            "path": "/foo",
            "uuid": None,
            "status": 200,
            "cookies": {"sess_id": None},
        }
        sess = session.Session(data)
        key = sess.get_uuid()
        self.assertIsNotNone(key)
