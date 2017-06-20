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
        self.handler = lfi.LfiEmulator()

    def test_handle_abspath_lfi(self):
        attack_params = [dict(id= 'foo', value= '/etc/passwd')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('root:x:0:0:root:/root:/bin/sh', result)

    def test_handle_relative_path_lfi(self):
        attack_params = [dict(id= 'foo', value= '../../../../../etc/passwd')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('root:x:0:0:root:/root:/bin/sh', result)

    def test_handle_missing_lfi(self):
        attack_params = [dict(id= 'foo', value= '../../../../../etc/bar')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('No such file or directory', result)
