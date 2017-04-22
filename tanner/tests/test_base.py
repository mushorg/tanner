import asyncio
import unittest
from unittest import mock

from tanner.emulators import base


class TestBase(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.session = mock.Mock()
        self.session.associate_db = mock.Mock()
        self.data = mock.Mock()
        with mock.patch('tanner.emulators.lfi.LfiEmulator', mock.Mock(), create=True):
            self.handler = base.BaseHandler('/tmp/', 'test.db', self.loop)

    def test_handle_get_sqli(self):
        path = '/index.html?id=1 UNION SELECT 1'

        @asyncio.coroutine
        def mock_sqli_check_get_data(path):
            return 1

        @asyncio.coroutine
        def mock_sqli_handle(path, session, post_request=0):
            return 'sqli_test_payload'

        self.handler.emulators['sqli'] = mock.Mock()
        self.handler.emulators['sqli'].check_get_data = mock_sqli_check_get_data
        self.handler.emulators['sqli'].handle = mock_sqli_handle

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'sqli', 'order': 2, 'payload': 'sqli_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_get_xss(self):
        path = '/index.html?id=<script>alert(1);</script>'

        @asyncio.coroutine
        def mock_xss_handle(path, session, post_request=0):
            return 'xss_test_payload'

        self.handler.emulators['xss'] = mock.Mock()
        self.handler.emulators['xss'].handle = mock_xss_handle

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'xss', 'order': 3, 'payload': 'xss_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_get_lfi(self):
        path = '/index.html?file=/etc/passwd'

        @asyncio.coroutine
        def mock_lfi_handle(path, session, post_request=0):
            return 'lfi_test_payload'

        self.handler.emulators['lfi'] = mock.Mock()
        self.handler.emulators['lfi'].handle = mock_lfi_handle

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'lfi', 'order': 2, 'payload': 'lfi_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_get_index(self):
        path = '/index.html'

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = detection = {'name': 'index', 'order': 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_get_lfi(self):
        path = '/wp-content'

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = detection = {'name': 'wp-content', 'order': 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_get_rfi(self):
        path = '/index.html?file=http://attack.php'

        @asyncio.coroutine
        def mock_rfi_handle(path, session, post_request=0):
            return 'rfi_test_payload'

        self.handler.emulators['rfi'] = mock.Mock()
        self.handler.emulators['rfi'].handle = mock_rfi_handle

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'rfi', 'order': 2, 'payload': 'rfi_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_post_xss(self):
        @asyncio.coroutine
        def mock_xss_handle(value, session, raw_data=None):
            return 'xss_test_payload'

        self.handler.emulators['xss'] = mock.Mock()
        self.handler.emulators['xss'].handle = mock_xss_handle

        @asyncio.coroutine
        def mock_sqli_check_post_data(data):
            return 1

        @asyncio.coroutine
        def mock_sqli_handle(path, session, post_request=0):
            return None

        self.handler.emulators['sqli'] = mock.Mock()
        self.handler.emulators['sqli'].check_post_data = mock_sqli_check_post_data
        self.handler.emulators['sqli'].handle = mock_sqli_handle

        detection = self.loop.run_until_complete(self.handler.handle_post(self.session, self.data))

        assert_detection = {'name': 'xss', 'order': 2, 'payload': 'xss_test_payload'}
        self.assertDictEqual(detection, assert_detection)
