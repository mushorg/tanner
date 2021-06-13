import asyncio
import unittest

from tanner.emulators import crlf


class TestCRLF(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.handler = crlf.CRLFEmulator()

    def test_scan(self):
        attack = "foo \r\n Set-Cookie : id=0"
        assert_result = dict(name="crlf", order=2)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_handle(self):
        attack_params = [dict(id="foo", value="bar \r\n Set-Cookie : id=0")]
        assert_result = {"foo": "bar \r\n Set-Cookie : id=0"}
        result = self.loop.run_until_complete(self.handler.handle(attack_params, None))
        self.assertEqual(result["headers"], assert_result)
