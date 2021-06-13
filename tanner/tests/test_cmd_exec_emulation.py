import unittest
from unittest import mock
import asyncio
from tanner.emulators import cmd_exec


class TestCmdExecEmulator(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.handler = cmd_exec.CmdExecEmulator()
        self.handler.helper.host_image = "busybox:latest"
        self.sess = mock.Mock()
        self.sess.sess_uuid.hex = "e86d20b858224e239d3991c1a2650bc7"

    def test_scan(self):
        attack = "id; uname"
        assert_result = dict(name="cmd_exec", order=3)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_scan_negative(self):
        attack = "id; curl"
        assert_result = None
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_handle_simple_command(self):
        attack_params = [dict(id="foo", value="id")]
        result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        assert_result = "uid=0(root) gid=0(root)"
        self.assertIn(assert_result, result["value"])

    def test_handle_nested_commands(self):
        attack_params = [[dict(id="foo1", value="id; uname")], [dict(id="foo2", value="id && uname")]]

        assert_result = {"id": "uid=0(root) gid=0(root)", "uname": "Linux"}
        for attack_param in attack_params:
            result = self.loop.run_until_complete(self.handler.handle(attack_param, self.sess))
            self.assertIn(assert_result["id"], result["value"])
            self.assertIn(assert_result["uname"], result["value"])

    def test_handle_invalid_commands(self):
        attack_params = [dict(id="foo", value="foo")]

        result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        assert_result = "sh: foo: not found"
        self.assertIn(assert_result, result["value"])

    def tearDown(self):
        self.loop.run_until_complete(self.handler.helper.docker_client.close())
        self.loop.close()
