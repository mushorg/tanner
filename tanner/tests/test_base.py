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

        def mock_lfi_scan(value):
            return dict(name= 'lfi', order= 0)

        self.handler.emulators['lfi'].scan = mock_lfi_scan

    def test_handle_sqli(self):
        path = '/index.html?id=1 UNION SELECT 1'

        async def mock_sqli_handle(path, session):
            return 'sqli_test_payload'

        def mock_sqli_scan(value):
            return dict(name= 'sqli', order= 2)

        self.handler.emulators['sqli'] = mock.Mock()
        self.handler.emulators['sqli'].handle = mock_sqli_handle
        self.handler.emulators['sqli'].scan = mock_sqli_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'sqli', 'order': 2, 'payload': 'sqli_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_xss(self):
        path = '/index.html?id=<script>alert(1);</script>'

        async def mock_xss_handle(path, session):
            return 'xss_test_payload'

        def mock_xss_scan(value):
            return dict(name= 'xss', order= 3)

        self.handler.emulators['xss'] = mock.Mock()
        self.handler.emulators['xss'].handle = mock_xss_handle
        self.handler.emulators['xss'].scan = mock_xss_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'xss', 'order': 3, 'payload': 'xss_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_lfi(self):
        path = '/index.html?file=/etc/passwd'

        async def mock_lfi_handle(attack_value, session):
            return 'lfi_test_payload'
        
        def mock_lfi_scan(value):
            return dict(name= 'lfi', order= 2)

        self.handler.emulators['lfi'] = mock.Mock()
        self.handler.emulators['lfi'].handle = mock_lfi_handle
        self.handler.emulators['lfi'].scan = mock_lfi_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'lfi', 'order': 2, 'payload': 'lfi_test_payload'}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_index(self):
        path = '/index.html'

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = detection = {'name': 'index', 'order': 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_wp_content(self):
        path = '/wp-content'

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = detection = {'name': 'wp-content', 'order': 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_rfi(self):
        path = '/index.html?file=http://attack.php'

        async def mock_rfi_handle(path, session):
            return 'rfi_test_payload'

        def mock_rfi_scan(value):
            return dict(name= 'rfi', order= 2)

        self.handler.emulators['rfi'] = mock.Mock()
        self.handler.emulators['rfi'].handle = mock_rfi_handle
        self.handler.emulators['rfi'].scan = mock_rfi_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, path))

        assert_detection = {'name': 'rfi', 'order': 2, 'payload': 'rfi_test_payload'}
        self.assertDictEqual(detection, assert_detection)