import os
import unittest
from unittest import mock
import asyncio
from tanner import config
from tanner.emulators import lfi
import yarl

class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        vdocs = os.path.join(os.getcwd(), 'data/vdocs.json')
        config.TannerConfig.get = mock.MagicMock(return_value=vdocs)
        self.handler = lfi.LfiEmulator('/tmp/')

    def test_handle_abspath_lfi(self):
        path = '/?foo=/etc/passwd'
        query = yarl.URL(path).query
        result = self.loop.run_until_complete(self.handler.handle(query['foo']))
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_relative_path_lfi(self):
        path = '/?foo=../../../../../etc/passwd'
        query = yarl.URL(path).query
        result = self.loop.run_until_complete(self.handler.handle(query['foo']))
        self.assertIn('root:x:0:0:root:/root:/bin/bash', result)

    def test_handle_missing_lfi(self):
        path = '/?foo=../../../../../etc/bar'
        query = yarl.URL(path).query
        result = self.loop.run_until_complete(self.handler.handle(query['foo']))
        self.assertIsNone(result)
