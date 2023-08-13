from unittest import mock

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from tanner.api import server, api


class TestAPIServer(AioHTTPTestCase):
    def setUp(self):
        self.serv = server.ApiServer()

        redis = mock.Mock()
        redis.close = mock.Mock()
        self.serv.redis_client = redis
        self.serv.api = api.Api(self.serv.redis_client)

        super(TestAPIServer, self).setUp()

    async def get_application(self):
        app = await self.serv.make_app()
        return app

    @unittest_run_loop
    async def test_api_index_request(self):
        assert_content = {"version": 1, "response": {"message": "tanner api"}}
        request = await self.client.request(
            "GET",
            "/?key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGFubmVyX293bmVyIn0."
            "NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snares_request(self):
        async def mock_return_snares():
            return ["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"]

        assert_content = {"version": 1, "response": {"message": ["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"]}}
        self.serv.api.return_snares = mock_return_snares
        request = await self.client.request(
            "GET",
            "/snares?key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            ".eyJ1c2VyIjoidGFubmVyX293bmVyIn0.NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snare_info_request(self):
        async def mock_return_snare_info(snare_uuid, count):
            if snare_uuid == "8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4" and count == 50:
                return [{"test_sess1": "sess1_info"}, {"test_sess1": "sess2_info"}]

        assert_content = {
            "version": 1,
            "response": {"message": [{"test_sess1": "sess1_info"}, {"test_sess1": "sess2_info"}]},
        }
        self.serv.api.return_snare_info = mock_return_snare_info
        request = await self.client.request(
            "GET",
            "/snare/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"
            "?key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGFubmVyX293bmVyIn0"
            ".NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snare_stats_request(self):
        async def mock_return_snare_stats(snare_uuid):
            if snare_uuid == "8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4":
                return {
                    "total_sessions": 605,
                    "total_duration": 865.560286283493,
                    "attack_frequency": {"sqli": 0, "lfi": 0, "xss": 0, "rfi": 0, "cmd_exec": 0},
                }

        assert_content = {
            "version": 1,
            "response": {
                "message": {
                    "total_sessions": 605,
                    "total_duration": 865.560286283493,
                    "attack_frequency": {"sqli": 0, "lfi": 0, "xss": 0, "rfi": 0, "cmd_exec": 0},
                }
            },
        }
        self.serv.api.return_snare_stats = mock_return_snare_stats
        request = await self.client.request(
            "GET",
            "/snare-stats/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4?key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            ".eyJ1c2VyIjoidGFubmVyX293bmVyIn0.NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_sessions_request(self):
        async def mock_return_sessions(filters):
            if (
                type(filters) is dict
                and filters["peer_ip"] == "127.0.0.1"
                and filters["start_time"] == 1497890400
                and filters["user_agent"] == "ngnix"
            ):
                return [
                    {"sess_uuid": "f387d46eaeb1454cadf0713a4a55be49"},
                    {"sess_uuid": "e85ae767b0bb4b1f91b421b3a28082ef"},
                ]

        assert_content = {
            "version": 1,
            "response": {"message": ["f387d46eaeb1454cadf0713a4a55be49", "e85ae767b0bb4b1f91b421b3a28082ef"]},
        }
        self.serv.api.return_sessions = mock_return_sessions
        request = await self.client.request(
            "GET",
            "/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4/sessions?filters=peer_ip:127.0.0.1 start_time:1497890400"
            " user_agent:ngnix&key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGFubmVyX293bmVyIn0."
            "NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )  # noqa
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_sessions_info_request(self):
        async def mock_return_session_info(sess_uuid):
            if sess_uuid == "4afd45d61b994d9eb3ba20faa81a45e1":
                return {"test_sess1": "sess1_info"}

        assert_content = {"version": 1, "response": {"message": {"test_sess1": "sess1_info"}}}
        self.serv.api.return_session_info = mock_return_session_info
        request = await self.client.request(
            "GET",
            "/session/4afd45d61b994d9eb3ba20faa81a45e1?key=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            ".eyJ1c2VyIjoidGFubmVyX293bmVyIn0.NQ7x_iq2t2SUs20Z9G-FmgqeNBOp5duiXr_auNVmzfU",
        )
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)
