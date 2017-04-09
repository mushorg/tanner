import asyncio
import unittest
from unittest import mock

from tanner import session, session_manager


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = session_manager.SessionManager(loop=self.loop)
        self.handler.analyzer = mock.Mock()
        self.handler.analyzer.send = mock.Mock()

    def test_validate_missing_peer(self):
        data = {
            'headers': {
                'USER-AGENT': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
            },
            'path': '/foo',
            'uuid': None,
            'cookies': {'sess_uuid': None}
        }

        assertion_data = {
            'peer': {'ip': None, 'port': None},
            'headers': {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
            },
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_validate_missing_user_agent(self):
        data = {
            'peer': {
                'ip': '127.0.0.1',
                'port': 80
            },
            'headers': {},
            'path': '/foo',
            'uuid': None,
            'cookies': {'sess_uuid': None}
        }

        assertion_data = {
            'peer': {
                'ip': '127.0.0.1',
                'port': 80
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_validate_missing_cookies(self):
        data = {
            'peer': {
                'ip': '127.0.0.1',
                'port': 80
            },
            'headers': {},
            'path': '/foo',
            'uuid': None
        }

        assertion_data = {
            'peer': {
                'ip': '127.0.0.1',
                'port': 80
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_adding_new_session(self):
        data = {
            'peer': {
            },
            'headers': {},
            'path': '/foo',
            'uuid': None,
            'cookies': {'sess_uuid': None}
        }
        sess = yield from self.handler.add_or_update_session(data)
        assertion_data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        assertion_session = session.Session(assertion_data)
        self.assertEquals(session, assertion_session)

    def test_updating_session(self):
        @asyncio.coroutine
        def sess_sadd(key, value):
            return None

        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        sess = session.Session(data)
        data['cookies']['sess_uuid'] = sess.get_uuid()
        redis_mock = mock.Mock()
        redis_mock.sadd = sess_sadd
        self.handler.sessions.append(sess)
        self.loop.run_until_complete(self.handler.add_or_update_session(data, redis_mock))
        self.assertEqual(self.handler.sessions[0].count, 2)

    def test_deleting_sessions(self):
        @asyncio.coroutine
        def sess_get(key):
            return b'{"sess_uuid": "c546114f97f548f982756495f963e280", "start_time": 1466091813.4780173, ' \
                   b'"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                   b'Chrome/53.0.2767.4 Safari/537.36", "end_time": 1466091899.9854035, ' \
                   b'"sensor": "78e51180-bf0d-4757-8a04-f000e5efa179", "count": 1, ' \
                   b'"paths": [{"timestamp": 1466091813.4779778, "path": "/", "attack_type": "index", "response_status": 200}]' \
                   b'"peer": {"port": 56970, "ip": "192.168.1.3"}, ' \
                   b'"cookies": {"sess_uuid": "c546114f97f548f982756495f963e280"}}'

        @asyncio.coroutine
        def sess_set(key, value):
            return None

        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_uuid': None}
        }
        sess = session.Session(data)
        sess.is_expired = mock.MagicMock(name='expired')
        sess.is_expired.__bool__.reurned_value = True
        self.handler.sessions.append(sess)
        redis_mock = mock.Mock()
        redis_mock.set = sess_set
        redis_mock.get = sess_get
        self.loop.run_until_complete(self.handler.delete_old_sessions(redis_mock))
        self.assertListEqual(self.handler.sessions, [])

    def test_get_uuid(self):
        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200,
            'cookies': {'sess_id': None}
        }
        sess = session.Session(data)
        key = sess.get_uuid()
        self.assertIsNotNone(key)
