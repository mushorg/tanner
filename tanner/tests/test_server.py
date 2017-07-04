import asyncio
import uuid
from unittest import mock

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from tanner import server, api
from tanner.config import TannerConfig


class TestServer(AioHTTPTestCase):
    def setUp(self):
        d = dict(MONGO={'enabled': 'False', 'URI': 'mongodb://localhost'},
                 LOCALLOG={'enabled': 'False', 'PATH': '/tmp/tanner_report.json'})
        m = mock.MagicMock()
        m.__getitem__.side_effect = d.__getitem__
        m.__iter__.side_effect = d.__iter__
        TannerConfig.config = m

        with mock.patch('tanner.dorks_manager.DorksManager', mock.Mock()):
            with mock.patch('tanner.emulators.base.BaseHandler', mock.Mock(), create=True):
                with mock.patch('tanner.session_manager.SessionManager', mock.Mock(), create=True):
                    self.serv = server.TannerServer()

        self.test_uuid = uuid.uuid4()


        async def _add_or_update_mock(data, client):
            sess = mock.Mock()
            sess.set_attack_type = mock.Mock()
            test_uuid = uuid
            sess.get_uuid = mock.Mock(return_value=str(self.test_uuid))
            return sess

        self.serv.session_manager.add_or_update_session = _add_or_update_mock

        async def choosed(client):
            return [x for x in range(10)]

        dorks = mock.Mock()
        dorks.choose_dorks = choosed
        dorks.extract_path = self._make_coroutine()

        redis = mock.Mock()
        redis.close = mock.Mock()
        self.serv.dorks = dorks
        self.serv.redis_client = redis
        self.serv.api = api.Api(self.serv.redis_client)

        super(TestServer, self).setUp()

    def _make_coroutine(self):
        async def coroutine(*args, **kwargs):
            return mock.Mock(*args, **kwargs)

        return coroutine

    def get_app(self):
        app = self.serv.create_app(loop=self.loop)
        api_app = self.serv.create_api_app(loop=self.loop)
        app.add_subapp('/api/', api_app)
        return app

    @unittest_run_loop
    async def test_example(self):
        request = await self.client.request("GET", "/")
        assert request.status == 200
        text = await request.text()
        assert "Tanner server" in text

    def test_make_response(self):
        msg = 'test'
        content = self.serv._make_response(msg)
        assert_content = dict(version=1, response=dict(message=msg))
        self.assertDictEqual(content, assert_content)

    @unittest_run_loop
    async def test_events_request(self):
        async def _make_handle_coroutine(*args, **kwargs):
            return {'name': 'index', 'order': 1, "payload": None}

        detection_assert = {'version': 1, 'response': {
            'message': {'detection': {'name': 'index', 'order': 1, "payload": None}, 'sess_uuid': str(self.test_uuid)}}}
        self.serv.base_handler.handle = _make_handle_coroutine
        request = await self.client.request("POST", "/event", data=b"{\"path\":\"/index.html\"}")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, detection_assert)

    @unittest_run_loop
    async def test_dorks_request(self):
        assert_content = dict(version=1, response=dict(dorks=[x for x in range(10)]))
        request = await self.client.request("GET", "/dorks")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_index_request(self):
        assert_content = {"version": 1, "response": {"message": "tanner api"}}
        request = await self.client.request("GET", "/api/")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snares_request(self):
        async def mock_return_snares(*args, **kwargs):
            return ["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"]

        assert_content = {"version": 1, "response": {"message": ["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"]}}
        self.serv.api.return_snares = mock_return_snares
        request = await self.client.request("GET", "/api/snares")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snare_info_request(self):
        async def mock_return_snare_info(*args, **kwargs):
            return [{"test_sess1": "sess1_info"}, {"test_sess1": "sess2_info"}]

        assert_content = {"version": 1, "response": {"message": [{"test_sess1": "sess1_info"}, {"test_sess1": "sess2_info"}]}}
        self.serv.api.return_snare_info = mock_return_snare_info
        request = await self.client.request("GET", "/api/snare/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_snare_stats_request(self):
        async def mock_return_snare_stats(*args, **kwargs):
            return {"total_sessions": 605, "total_duration": 865.560286283493, "attack_frequency": {"sqli": 0, "lfi": 0, "xss": 0, "rfi": 0, "cmd_exec": 0}}

        assert_content = {"version": 1, "response": {"message": {"total_sessions": 605, "total_duration": 865.560286283493, "attack_frequency": {"sqli": 0, "lfi": 0, "xss": 0, "rfi": 0, "cmd_exec": 0}}}}
        self.serv.api.return_snare_stats = mock_return_snare_stats
        request = await self.client.request("GET", "/api/snare-stats/8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_sessions_request(self):
        async def mock_return_sessions(*args, **kwargs):
            return ["f387d46eaeb1454cadf0713a4a55be49", "e85ae767b0bb4b1f91b421b3a28082ef"]

        assert_content = {"version": 1, "response": {"message": ["f387d46eaeb1454cadf0713a4a55be49", "e85ae767b0bb4b1f91b421b3a28082ef"]}}
        self.serv.api.return_sessions = mock_return_sessions
        request = await self.client.request("GET", "/api/sessions?filters=peer_ip:127.0.0.1 time_interval:1497890400-1497890450")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_api_sessions_info_request(self):
        async def mock_return_session_info(*args, **kwargs):
            return {"test_sess1": "sess1_info"}

        assert_content = {"version": 1, "response": {"message": {"test_sess1": "sess1_info"}}}
        self.serv.api.return_session_info = mock_return_session_info
        request = await self.client.request("GET", "/api/session/4afd45d61b994d9eb3ba20faa81a45e1")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)