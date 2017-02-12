import unittest
from unittest import mock
import os
from tanner.emulators import lfi
from tanner import config


class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        vdocs = os.path.join(os.getcwd(),'data/vdocs.json')
        config.TannerConfig.get = mock.MagicMock(return_value=vdocs)
        self.handler = lfi.LfiEmulator('/tmp/')

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
