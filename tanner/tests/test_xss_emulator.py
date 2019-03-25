import asyncio

import unittest

from tanner.emulators import xss


class TestXSSEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = xss.XssEmulator()

    def test_scan(self):
        attack = '<script>alert(1);</script>'
        assert_result = dict(name='xss', order=3)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_scan_negative(self):
        attack = 'alert(1);'
        assert_result = None
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_multiple_xss(self):
        attack_params = [dict(id='comment', value='<script>alert(\'comment\');</script>'),
                         dict(id='name', value='<script>alert(\'name\');</script>'),
                         dict(id='email', value='<script>alert(\'email\');</script>')]
        xss = self.loop.run_until_complete(self.handler.handle(attack_params, None))
        assert_result = '<script>alert(\'name\');</script>'
        self.assertIn(assert_result, xss['value'])

    def test_xss(self):
        attack_params = [dict(id='foo', value='<script>alert(\'xss\');</script>')]
        xss = self.loop.run_until_complete(self.handler.handle(attack_params, None))

        assert_result = dict(value=attack_params[0]['value'], page=True)
        self.assertDictEqual(xss, assert_result)
