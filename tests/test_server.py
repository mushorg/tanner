import asyncio
import unittest

from unittest import mock


class TestServer(unittest.TestCase):

    MockedRequestHandler = None

    def setUp(self):
        with mock.patch('builtins.open', mock.mock_open(), create=True):
            with mock.patch('pickle.load', mock.Mock(), create=True):
                import server
                self.MockedRequestHandler = server.HttpRequestHandler

    def test_handle_request_for_dorks(self):
        srv = self.MockedRequestHandler(debug=False, keep_alive=75)
        srv.writer = mock.Mock()
        m = mock.Mock()
        m_eof = mock.Mock()
        m_eof.return_value = (lambda: (yield None))()
        rand = mock.Mock()
        rand.return_value = [x for x in range(10)]

        with mock.patch('aiohttp.Response.write', m, create=True):
            with mock.patch('aiohttp.Response.write_eof', m_eof, create=True):
                with mock.patch('random.sample', rand, create=True):
                    message = mock.Mock()
                    message.headers = []
                    message.path = '/dorks'
                    message.version = (1, 1)

                    asyncio.get_event_loop().run_until_complete(srv.handle_request(message, None))

                    content = b''.join([c[1][0] for c in list(m.mock_calls)]).decode('utf-8')
                    content = eval(content)
                    assert_content = dict(version=1, response=dict(dorks=[x for x in range(10)]))

                    self.assertDictEqual(content, assert_content)