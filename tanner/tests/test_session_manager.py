import unittest
from unittest import mock

from tanner import session, session_manager


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.handler = session_manager.SessionManager()
        self.handler.analyzer = mock.Mock()
        self.handler.analyzer.send = mock.Mock()

    def test_validate_missing_peer(self):
        data = {
            'headers': {
                'USER-AGENT': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
            },
            'path': '/foo',
            'uuid': None
        }

        assertion_data = {
            'peer': {'ip': None, 'port': None},
            'headers': {
                'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
            },
            'path': '/foo',
            'uuid': None,
            'status': 200
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
            'status': 200
        }
        data = self.handler.validate_data(data)
        self.assertDictEqual(data, assertion_data)

    def test_adding_new_session(self):
        data = {
            'peer': {
            },
            'headers': {},
            'path': '/foo',
            'uuid': None
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
            'status': 200
        }
        assertion_session = session.Session(assertion_data)
        self.assertEquals(session, assertion_session)

    def test_updating_session(self):
        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200
        }
        sess = session.Session(data)
        self.handler.sessions.append(sess)
        yield from self.handler.add_or_update_session(data)
        self.assertEqual(self.handler.sessions[0].count, 2)

    def test_deleting_sessions(self):
        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200
        }
        sess = session.Session(data)
        sess.is_expired = mock.MagicMock(name='expired')
        sess.is_expired.__bool__.reurned_value = True
        self.handler.sessions.append(sess)
        experied = mock.Mock()
        experied.return_value = True
        yield from self.handler.delete_old_sessions()
        self.assertListEqual(self.handler.sessions, [])

    def test_get_key(self):
        data = {
            'peer': {
                'ip': None,
                'port': None
            },
            'headers': {'user-agent': None},
            'path': '/foo',
            'uuid': None,
            'status': 200
        }
        sess = session.Session(data)
        key = sess.get_key()
        self.assertIsNotNone(key)
