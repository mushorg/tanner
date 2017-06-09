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

    def test_multiple_xss(self):
        attack_params = [dict(id= 'comment', value= '<script>alert(\'comment\');</script>'),
                        dict(id= 'name', value= '<script>alert(\'name\');</script>'),
                        dict(id= 'email', value= '<script>alert(\'email\');</script>')]
        xss = self.loop.run_until_complete(self.handler.handle(attack_params, None))
        assert_result = '<script>alert(\'name\');</script>'
        self.assertIn(assert_result, xss['value'])

    def test_xss(self):
        attack_params = [dict(id= 'foo', value= '<script>alert(\'xss\');</script>')]
        xss = self.loop.run_until_complete(self.handler.handle(attack_params, None))

        assert_result = dict(value=attack_params[0]['value'],
                             page='/index.html')
        self.assertDictEqual(xss, assert_result)

    def test_set_xss_page(self):
        paths = [{'path': '/python.html', 'timestamp': 1465851064.2740946},
                 {'path': '/python.php/?foo=bar', 'timestamp': 1465851065.2740946},
                 {'path': '/python.html/?foo=bar', 'timestamp': 1465851065.2740946}]
        with mock.patch('tanner.session.Session') as mock_session:
            mock_session.return_value.paths = paths
            sess = session.Session(None)
        attack_params = [dict(id= 'foo', value= '<script>alert(\'xss\');</script>')]
        xss = self.loop.run_until_complete(self.handler.handle(attack_params, sess))
        self.assertEqual(xss['page'], '/python.html')
