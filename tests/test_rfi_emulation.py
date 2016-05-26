import unittest
import rfi_emulator
import asyncio
import aiohttp


class TestRfiEmulator(unittest.TestCase):
    def setUp(self):
        self.handler = rfi_emulator.RfiEmulator()

    def test_http_download(self):
        path = 'file=http://example.com'
        data = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_http_download_fail(self):
        path = 'file=http://foobarfvfd'

        with self.assertRaises(aiohttp.errors.ClientOSError):
            yield from self.handler.download_file(path)

    def test_ftp_download(self):
        path = 'file=ftp://mirror.yandex.ru/archlinux/lastupdate'
        data = asyncio.get_event_loop().run_until_complete(self.handler.download_file(path))
        self.assertIsNotNone(data)

    def test_ftp_download_fail(self):
        path = 'file=ftp://mirror.yandex.ru/archlinux/foobar'
        with self.assertRaises(aiohttp.errors.ClientOSError):
            yield from self.handler.download_file(path)

    def test_get_result_faild(self):
        data = "test data"
        with self.assertRaises(aiohttp.errors.ClientOSError):
            yield from self.handler.get_rfi_result(data)
