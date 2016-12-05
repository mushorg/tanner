import asyncio
import unittest

import aiohttp

from tanner.emulators import rfi


class TestRfiEmulator(unittest.TestCase):
    def setUp(self):
        self.handler = rfi.RfiEmulator('/tmp/')

    def test_http_download(self):
        path = 'file=http://example.com'
        data = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_http_download_fail(self):
        path = 'file=http://foobarfvfd'
        filename = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNone(filename)

    def test_ftp_download(self):
        path = 'file=ftp://mirror.yandex.ru/archlinux/lastupdate'
        data = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_ftp_download_fail(self):
        path = 'file=ftp://mirror.yandex.ru/archlinux/foobar'
        with self.assertRaises(aiohttp.errors.ClientOSError):
            yield from self.handler.download_file(path)

    def test_get_result_fail(self):
        data = "test data"
        with self.assertRaises(aiohttp.errors.ClientOSError):
            yield from self.handler.get_rfi_result(data)

    def test_invalid_scheme(self):
        path = 'file=file://mirror.yandex.ru/archlinux/foobar'
        data = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNone(data)