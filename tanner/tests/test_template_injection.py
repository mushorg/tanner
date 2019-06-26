import asyncio
import unittest

from tanner.emulators.template_injection import TemplateInjection


class TestTemplateInjection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = TemplateInjection(loop=self.loop)
        self.result = None
        self.expected_result = None
        self.returned_result = None

    def test_scan(self):
        payload = '{{config}}'

        self.expected_result = dict(name='template_injection', order=3)
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_scan_negative(self):
        payload = '{7*7}'

        self.expected_result = None
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle_mako(self):
        payload = "<%\nimport os\nx=os.popen('id').read()\n%>${x}"

        self.returned_result = self.handler.get_injection_result(payload)
        self.expected_result = 'uid=0(root) gid=0(root) groups=0(root)'
        self.assertIn(self.expected_result, self.returned_result)

    def test_handle_jinja2(self):
        payload = '{{ 7*"7" }}'

        self.returned_result = self.handler.get_injection_result(payload)
        self.expected_result = '7777777'
        self.assertIn(self.expected_result, self.returned_result)

    def test_handle_tornado(self):
        payload = '{%import os%}{{os.popen("cat /etc/passwd").read()}}'

        self.returned_result = self.handler.get_injection_result(payload)
        self.expected_result = b'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin'

        self.assertIn(self.expected_result, self.returned_result)
