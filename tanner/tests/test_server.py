import uuid
from unittest import mock
import hashlib

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from tanner import server
from tanner.config import TannerConfig
from tanner.utils.asyncmock import AsyncMock
from tanner import __version__ as tanner_version


class TestServer(AioHTTPTestCase):
    def setUp(self):
        d = dict(
            MONGO={"enabled": "False", "URI": "mongodb://localhost"},
            LOCALLOG={"enabled": "False", "PATH": "/tmp/tanner_report.json"},
        )
        m = mock.MagicMock()
        m.__getitem__.side_effect = d.__getitem__
        m.__iter__.side_effect = d.__iter__

        with mock.patch("tanner.tests.test_server.TannerConfig") as p:

            TannerConfig.config = m
            TannerConfig.get = m.get

        with mock.patch("tanner.dorks_manager.DorksManager", mock.Mock()):
            with mock.patch("tanner.emulators.base.BaseHandler", mock.Mock(), create=True):
                with mock.patch("tanner.sessions.session_manager.SessionManager", mock.Mock(), create=True):
                    self.serv = server.TannerServer()

        self.test_uuid = uuid.uuid4()

        async def _add_or_update_mock(data, client):
            sess = mock.Mock()
            sess.set_attack_type = mock.Mock()
            sess_id = hashlib.md5(b"foo")
            test_uuid = uuid
            sess.get_uuid = mock.Mock(return_value=str(self.test_uuid))
            return sess, sess_id

        async def _delete_sessions_mock(client):
            pass

        self.serv.session_manager.add_or_update_session = _add_or_update_mock
        self.serv.session_manager.delete_sessions_on_shutdown = _delete_sessions_mock

        async def choosed(client):
            return [x for x in range(10)]

        dorks = mock.Mock()
        dorks.choose_dorks = choosed
        dorks.extract_path = self._make_coroutine()

        redis = AsyncMock()
        redis.close = AsyncMock()
        self.serv.dorks = dorks
        self.serv.redis_client = redis

        super(TestServer, self).setUp()

    def _make_coroutine(self):
        async def coroutine(*args, **kwargs):
            return mock.Mock(*args, **kwargs)

        return coroutine

    async def get_application(self):
        app = await self.serv.make_app()
        return app

    @unittest_run_loop
    async def test_example(self):
        request = await self.client.request("GET", "/")
        assert request.status == 200
        text = await request.text()
        assert "Tanner server" in text

    def test_make_response(self):
        msg = "test"
        content = self.serv._make_response(msg)
        assert_content = dict(version=tanner_version, response=dict(message=msg))
        self.assertDictEqual(content, assert_content)

    @unittest_run_loop
    async def test_events_request(self):
        async def _make_handle_coroutine(*args, **kwargs):
            return {"name": "index", "order": 1, "payload": None}

        detection_assert = {
            "version": tanner_version,
            "response": {
                "message": {
                    "detection": {"name": "index", "order": 1, "payload": None},
                    "sess_uuid": str(self.test_uuid),
                }
            },
        }
        self.serv.base_handler.handle = _make_handle_coroutine
        request = await self.client.request("POST", "/event", data=b'{"path":"/index.html"}')
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, detection_assert)

    @unittest_run_loop
    async def test_dorks_request(self):
        assert_content = dict(version=tanner_version, response=dict(dorks=[x for x in range(10)]))
        request = await self.client.request("GET", "/dorks")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)

    @unittest_run_loop
    async def test_version(self):
        assert_content = dict(version=tanner_version)
        request = await self.client.request("GET", "/version")
        assert request.status == 200
        detection = await request.json()
        self.assertDictEqual(detection, assert_content)
