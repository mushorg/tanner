import lfi_emulator
import unittest
import os


class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        data_path = os.path.split(os.path.abspath(os.getcwd()))[0]
        self.handler = lfi_emulator.LfiEmulator(data_path)

    def test_handle_abspath_lfi(self):
        path = '/?foo=/etc/passwd'
        result = self.handler.handle(path)
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_relative_path_lfi(self):
        path = '/?foo=../../../../../etc/passwd'
        result = self.handler.handle(path)
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_missing_lfi(self):
        path = '/?foo=../../../../../etc/bar'
        result = self.handler.handle(path)
        self.assertIsNone(result)
