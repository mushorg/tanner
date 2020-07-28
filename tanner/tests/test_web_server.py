import asyncio
from unittest import mock

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from tanner.api.api import Api
from tanner.utils.asyncmock import AsyncMock
from tanner.web.server import TannerWebServer


class TestWebServer(AioHTTPTestCase):
    def setUp(self):
        self.handler = TannerWebServer()
        postgres = AsyncMock()
        postgres.close = mock.Mock()
        self.handler.pg_client = postgres
        self.handler.api = Api(self.handler.pg_client)

        self.returned_content = None
        self.expected_content = None

        super(TestWebServer, self).setUp()

    def get_app(self):
        app = self.handler.create_app(loop=self.loop)
        return app

    @unittest_run_loop
    async def test_handle_index(self):
        self.handler.api.return_snares = AsyncMock(return_value=["foo"])
        self.handler.api.return_latest_session = AsyncMock()
        response = await self.client.request("GET", "/")
        self.returned_content = await response.text()

        self.assertEqual(response.status, 200)

    @unittest_run_loop
    async def test_handle_snares(self):
        self.handler.api.return_snares = AsyncMock(
            return_value=["9a631aee-2b52-4108-9831-b495ac8afa80"]
        )

        response = await self.client.request("GET", "/snares")
        self.returned_content = await response.text()

        self.expected_content = (
            '<a href="/snare/9a631aee-2b52-4108-9831-b495ac8afa80">'
            "9a631aee-2b52-4108-9831-b495ac8afa80</a>"
        )
        self.assertIn(self.expected_content, self.returned_content)

    @unittest_run_loop
    async def test_handle_snare(self):

        response = await self.client.request(
            "GET", "/snare/9a631aee-2b52-4108-9831-b495ac8afa80"
        )

        self.returned_content = await response.text()

        self.expected_content = (
            "<title>Snare(9a631aee-2b52-4108-9831-b495ac8afa80) - Tanner Web</title>"
        )
        self.assertIn(self.expected_content, self.returned_content)

    @unittest_run_loop
    async def test_handle_snare_stats(self):

        content = {
            "attack_frequency": {"cmd_exec": 1, "lfi": 2, "rfi": 1, "sqli": 0, "xss": 1}
        }

        self.handler.api.return_snare_stats = AsyncMock(return_value=content)

        response = await self.client.request(
            "GET", "/snare-stats/9a631aee-2b52-4108-9831-b495ac8afa80"
        )
        self.returned_content = await response.text()
        self.clear_returned_content = "".join(self.returned_content.split()[65:-8])
        self.expected_content = (
            "<tr><td><b>AttackFrequency</b></td><td>cmd_exec:1<br>lfi:2"
            "<br>rfi:1<br>sqli:0<br>xss:1<br></td>"
        )
        self.assertEqual(self.expected_content, self.clear_returned_content.strip())

    @unittest_run_loop
    async def test_handle_sessions(self):
        async def mock_return_sessions(filters):
            if (
                filters["peer_ip"] == "127.0.0.1"
                and filters["start_time"] == "11-05-2020"
                and filters["user_agent"] == "Mozilla/5.0"
            ):

                return [
                    {"sess_uuid": "f387d46eaeb1454cadf0713a4a55be49"},
                    {"sess_uuid": "e85ae767b0bb4b1f91b421b3a28082ef"},
                ]

        self.handler.api.return_sessions = mock_return_sessions

        response = await self.client.request(
            "GET",
            "/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4/sessions/page/2?filters=peer_ip:127.0.0.1 start_time:11-05-2020 user_agent:Mozilla/5.0",  # noqa
        )
        self.returned_content = await response.text()

        self.expected_content = """<th>Session-uuid</th>\n    <th>IP</th>\n    <th>Owner</th>\n  </tr>\n  \n</table>\n<br>\n<div align="center">\n  <a href="/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4/sessions/page/1?filters=peer_ip:127.0.0.1 start_time:11-05-2020 user_agent:Mozilla/5.0">"""  # noqa

        self.assertIn(self.expected_content, self.returned_content)

    @unittest_run_loop
    async def test_handle_sessions_error(self):

        with self.assertLogs(level="ERROR") as log:
            response = await self.client.request(
                "GET",
                "/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4/sessions/page/1?filters=peerip",
            )  # noqa

            self.assertIn("Filter error :", log.output[0])

    @unittest_run_loop
    async def test_sessions_info(self):
        session = dict(
            cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"},
            owners={"user": 1.0},
            attack_count={"lfi": 1},
        )

        self.handler.api.return_session_info = AsyncMock(return_value=session)

        self.expected_content = "<td><b>Cookies</b></td>\n    <td>\n    \n      sess_uuid : 9f82e5d0e6b64047bba996222d45e72c <br>\n    \n    </td>"  # noqa

        response = await self.client.request(
            "GET", "/session/da1811cd19d748058bc02ee5bf9029d4"
        )
        self.returned_content = await response.text()

        self.assertIn(self.expected_content, self.returned_content)
