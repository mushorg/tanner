import asyncio
import unittest
import os

from unittest import mock
from tanner.utils import patterns
from tanner.utils.asyncmock import AsyncMock
from tanner.emulators.template_injection import TemplateInjection


class TestTemplateInjection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.handler = TemplateInjection(loop=self.loop)
        self.result = None
        self.expected_result = None
        self.returned_result = None
        self.sess = mock.Mock()
        self.sess.sess_uuid.hex = "e86d20b858224e239d3991c1a2650bc7"
        self.handler.remote_path = (
            "https://raw.githubusercontent.com/mushorg/tanner/master/docker/" "tanner/template_injection/Dockerfile"
        )

    def test_scan(self):
        payload = "{{7*7}}"

        self.expected_result = dict(name="template_injection", order=4)
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_scan_negative(self):
        payload = "{7*7}"

        self.expected_result = None
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_xss_mako_regex(self):
        # xss payloads cannot be matched with mako's regex but vice versa is possible
        test_xss = '<img/src="1"/onerror=alert(0)>'  # space bypass xss payload
        verify_xss = patterns.XSS_ATTACK.match(test_xss)
        self.returned_result = self.handler.scan(test_xss)
        self.expected_result = None
        self.assertEqual(self.returned_result, self.expected_result)
        self.assertTrue(verify_xss)

    def test_handle_tornado(self):
        self.handler.docker_helper.execute_cmd = AsyncMock(return_value='posix.uname_result(sysname="Linux")')
        payload = "{%import os%}{{os.uname()}}"

        attack_params = [dict(id="foo", value=payload)]
        self.returned_result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        self.expected_result = os.uname()

        self.assertIn(self.expected_result[0], self.returned_result["value"])

    def test_handle_mako(self):
        self.handler.docker_helper.execute_cmd = AsyncMock(return_value='posix.uname_result(sysname="Linux")')
        payload = "<%\nimport os\nx=os.uname()\n%>\n${x}"

        attack_params = [dict(id="foo", value=payload)]
        self.returned_result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        self.expected_result = os.uname()
        self.assertIn(self.expected_result[0], self.returned_result["value"])

    def tearDown(self):
        self.loop.run_until_complete(self.handler.docker_helper.docker_client.close())
        self.loop.close()
