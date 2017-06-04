import asyncio

import unittest
from unittest import mock

from tanner import session
from tanner.emulators import xss


class TestXSSEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = xss.XssEmulator()

    def test_post_xss(self):
        data = {
            'post_data': {'comment': '<script>alert(\'xss\');</script>'}
        }
        xss = self.loop.run_until_complete(self.handler.handle(None, None, data))
        assert_result = dict(value='<script>alert(\'xss\');</script>',
                             page='/index.html')
        self.assertDictEqual(xss, assert_result)

    def test_multiple_post_xss(self):
        data = {
            'post_data': {'comment': '<script>alert(\'comment\');</script>',
                          'name': '<script>alert(\'name\');</script>',
                          'email': '<script>alert(\'email\');</script>'}
        }
        xss = self.loop.run_until_complete(self.handler.handle(None, None, data))
        assert_result = '<script>alert(\'name\');</script>'
        self.assertIn(assert_result, xss['value'])

    def test_get_xss(self):
        path = '/python.php/?foo=<script>alert(\'xss\');</script>'
        xss = self.loop.run_until_complete(self.handler.handle(path, None,  None))

        assert_result = dict(value=path,
                             page='/index.html')
        self.assertDictEqual(xss, assert_result)

    def test_set_xss_page(self):
        paths = [{'path': '/python.html', 'timestamp': 1465851064.2740946},
                 {'path': '/python.php/?foo=bar', 'timestamp': 1465851065.2740946},
                 {'path': '/python.html/?foo=bar', 'timestamp': 1465851065.2740946}]
        with mock.patch('tanner.session.Session') as mock_session:
            mock_session.return_value.paths = paths
            sess = session.Session(None)
        data = {
            'post_data': {'comment': '<script>alert(\'xss\');</script>'}
        }
        xss = self.loop.run_until_complete(self.handler.handle(None, sess, data))
        self.assertEqual(xss['page'], '/python.html')
