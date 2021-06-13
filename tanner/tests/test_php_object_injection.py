import asyncio
import unittest

from tanner.utils.asyncmock import AsyncMock
from tanner.emulators.php_object_injection import PHPObjectInjection


class TestPHPCodeInjection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = PHPObjectInjection(loop=self.loop)
        self.result = None
        self.expected_result = None
        self.returned_result = None

    def test_scan(self):
        payload = 'O:15:"ObjectInjection":1:{s:6:"insert";s:2:"id";}'

        self.expected_result = dict(name="php_object_injection", order=3)
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_scan_negative(self):
        payload = 'O:"ObjectInjection":1:{s:6:"insert";s:2:"id";}'

        self.expected_result = None
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle_status_code(self):
        self.handler.get_injection_result = AsyncMock(return_value=None)

        attack_params = [dict(id="foo", value="O:15:'ObjectInjection':1:{s:6:'insert';}")]
        self.expected_result = dict(status_code=504)

        async def test():

            self.returned_result = await self.handler.handle(attack_params)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle(self):
        attack_params = [dict(id="foo", value='O:15:"ObjectInjection":1:{s:6:"insert";s:2:"id";}')]
        self.handler.helper.get_result = AsyncMock(
            return_value={
                "file_md5": "a43deb0f2d7904cbb6c27c02ed7c2593",
                "stdout": "id=0(root) gid=0(root) groups=0(root)",
            }
        )

        self.expected_result = "id=0(root) gid=0(root) groups=0(root)"

        async def test():

            self.returned_result = await self.handler.handle(attack_params)

        self.loop.run_until_complete(test())
        self.assertIn(self.expected_result, self.returned_result["value"])
