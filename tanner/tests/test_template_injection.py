import asyncio
import unittest
import os

from unittest import mock
from tanner.config import TannerConfig
from tanner.utils.aiodocker_helper import AIODockerHelper
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
        self.sess.sess_uuid.hex = 'e86d20b858224e239d3991c1a2650bc7'
        self.docker_helper = AIODockerHelper()
        self.handler.remote_path = 'https://raw.githubusercontent.com/mushorg/tanner/master/docker/' \
                                   'tanner/template_injection/Dockerfile'

    def test_scan(self):
        payload = '{{7*7}}'

        self.expected_result = dict(name='template_injection', order=3)
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_scan_negative(self):
        payload = '{7*7}'

        self.expected_result = None
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle_tornado(self):
        payload = '{%import os%}{{os.uname()}}'

        attack_params = [dict(id='foo', value=payload)]
        self.returned_result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        self.expected_result = os.uname()

        self.assertIn(self.expected_result[0], self.returned_result['value'])

    def test_handle_mako(self):
        payload = '<%\nimport os\nx=os.uname()\n%>\n${x}'

        attack_params = [dict(id='foo', value=payload)]
        self.returned_result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        self.expected_result = os.uname()
        self.assertIn(self.expected_result[0], self.returned_result['value'])

    def tearDown(self):
        self.loop.run_until_complete(self.handler.docker_helper.docker_client.close())
        self.loop.close()
