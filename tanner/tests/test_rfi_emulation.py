import asyncio
import unittest
from unittest import mock
from tanner.emulators import rfi

class TestRfiEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = rfi.RfiEmulator('/tmp/', loop=self.loop)

    def test_http_download(self):
        path = 'http://example.com'
        data = self.loop.run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_http_download_fail(self):
        path = 'http://foobarfvfd'
        filename = self.loop.run_until_complete(self.handler.download_file(path))
        self.assertIsNone(filename)
        
    def test_ftp_download(self):
        self.handler.download_file_ftp = mock.MagicMock(return_value = '10ddd27e6bab5c8e2aa356906d1b71e5')
        path = 'ftp://mirror.yandex.ru/archlinux/lastupdate'
        data = self.loop.run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_ftp_download_fail(self):
        path = 'ftp://mirror.yandex.ru/archlinux/foobar'

        with self.assertLogs():
            self.loop.run_until_complete(self.handler.download_file(path))

    def test_get_result_fail(self):
        data = "test data"
        result = self.loop.run_until_complete(self.handler.get_rfi_result(data))
        self.assertIsNone(result)

    def test_invalid_scheme(self):
        path = 'file://mirror.yandex.ru/archlinux/foobar'
        data = self.loop.run_until_complete(self.handler.download_file(path))
        self.assertIsNone(data)
