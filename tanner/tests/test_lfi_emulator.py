import unittest
from unittest import mock
import os
from tanner.emulators import lfi
from tanner import config


class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        d=dict(DATA={'vdocs':os.path.join(os.getcwd(),'data/vdocs.json')})
        m = mock.MagicMock()
        m.__getitem__.side_effect = d.__getitem__
        m.__iter__.side_effect = d.__iter__
        config.TannerConfig.config = m
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
