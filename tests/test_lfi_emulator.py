import lfi_emulator
import unittest
import os


class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        self.handler = lfi_emulator.LfiEmulator('/tmp/')

    def test_handle_abspath_lfi(self):
        path = '/?foo=/etc/passwd'
        result = yield from self.handler.handle(path)
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_relative_path_lfi(self):
        path = '/?foo=../../../../../etc/passwd'
        result = yield from self.handler.handle(path)
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_missing_lfi(self):
        path = '/?foo=../../../../../etc/bar'
        result = yield from self.handler.handle(path)
        self.assertIsNone(result)
