import unittest
import asyncio
from tanner.emulators import lfi


class TestLfiEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = lfi.LfiEmulator()
        self.handler.helper.host_image = 'busybox:latest'

    def test_scan(self):
        attack = '/etc/passwd'
        assert_result = dict(name='lfi', order=2)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_handle_abspath_lfi(self):
        attack_params = [dict(id='foo', value='/etc/passwd')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('root:x:0:0:root:/root:/bin/sh', result['value'])

    def test_handle_relative_path_lfi(self):
        attack_params = [dict(id='foo', value='../../../../../etc/passwd')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('root:x:0:0:root:/root:/bin/sh', result['value'])

    def test_handle_path_null_character(self):
        attack_params = [dict(id='foo', value='/etc/passwd\x00\x00')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('root:x:0:0:root:/root:/bin/sh', result['value'])

    def test_handle_missing_lfi(self):
        attack_params = [dict(id='foo', value='../../../../../etc/bar')]
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertIn('No such file or directory', result['value'])
