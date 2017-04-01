import uuid
from unittest import mock

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from tanner import new_server
from tanner.config import TannerConfig


class TestNewServer(AioHTTPTestCase):
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
                    self.serv = new_server.TannerServer()

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

        self.serv.dorks = dorks

        super(TestNewServer, self).setUp()

    def _make_coroutine(self):
        async def coroutine(*args, **kwargs):
            return mock.Mock(*args, **kwargs)

        return coroutine

    def get_app(self, loop):
        app = self.serv.create_app(loop=loop)
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
            return {"method": "GET", "path": "/index.html"}

        detection_assert = {'version': 1, 'response': {
            'message': {'detection': {'method': 'GET', 'path': '/index.html'}, 'sess_uuid': str(self.test_uuid)}}}
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
    async def test_api_request(self):
        assert_content = {"version": 1, "response": {"message": "tanner api"}}
        request = await self.client.request("GET", "/api")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_stats_api_request(self):
        async def _make_api_coroutine(*args, **kwargs):
            return ["1", "2"]

        assert_content = {"version": 1, "response": {"message": ["1", "2"]}}
        self.serv.api.handle_api_request = _make_api_coroutine
        request = await self.client.request("GET", "/api/stats")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)
