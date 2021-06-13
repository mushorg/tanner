import asyncio
import unittest

from tanner.emulators import php_code_injection


class TestPHPCodeInjection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = php_code_injection.PHPCodeInjection(loop=self.loop)

    def test_scan(self):
        attack = "; phpinfo();"
        assert_result = dict(name="php_code_injection", order=3)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_handle_status_code(self):
        async def mock_get_injection_results(code):
            return None

        self.handler.get_injection_result = mock_get_injection_results
        attack_params = [dict(id="foo", value=";sleep(50);")]
        assert_result = dict(status_code=504)
        result = self.loop.run_until_complete(self.handler.handle(attack_params))
        self.assertEqual(result, assert_result)
