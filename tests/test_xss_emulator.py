import unittest
import xss_emulator
import session
from unittest import mock


class TestXSSEmulator(unittest.TestCase):
    def setUp(self):
        self.handler = xss_emulator.XssEmulator()

    def test_post_xss(self):
        data = {
            'post_data': {'comment': '<script>alert(\'xss\');</script>'}
        }
        xss = self.handler.handle(None, None, data)
        assert_result = dict(name='xss', value='<script>alert(\'xss\');</script>',
                             page='/index.html')
        self.assertDictEqual(xss, assert_result)

    def test_multiple_post_xss(self):
        data = {
            'post_data': {'comment': '<script>alert(\'comment\');</script>',
                          'name': '<script>alert(\'name\');</script>',
                          'email': '<script>alert(\'email\');</script>'}
        }
        xss = self.handler.handle(None, None, data)
        assert_result = '<script>alert(\'name\');</script>'
        self.assertIn(assert_result, xss['value'])

    def test_get_xss(self):
        path = '/python.php/?foo=<script>alert(\'xss\');</script>'
        xss = self.handler.handle(None, path, None)

        assert_result = dict(name='xss', value=path,
                             page='/index.html')
        self.assertDictEqual(xss, assert_result)

    def test_set_xss_page(self):
        paths = [{'path': '/python.html', 'timestamp': 1465851064.2740946},
                 {'path': '/python.php/?foo=bar', 'timestamp': 1465851065.2740946},
                 {'path': '/python.html/?foo=bar', 'timestamp': 1465851065.2740946}]
        with mock.patch('session.Session') as mock_session:
            mock_session.return_value.paths = paths
            sess = session.Session(None)
        data = {
            'post_data': {'comment': '<script>alert(\'xss\');</script>'}
        }
        xss = self.handler.handle(sess, None, data)
        self.assertEqual(xss['page'], '/python.html')
