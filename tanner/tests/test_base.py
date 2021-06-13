import asyncio
import unittest
from unittest import mock

from tanner.utils.asyncmock import AsyncMock
from tanner.sessions import session
from tanner.emulators import base
from tanner import __version__ as tanner_version


class TestBase(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.session = mock.Mock()
        self.session.associate_db = mock.Mock()
        self.data = mock.Mock()
        with mock.patch("tanner.emulators.lfi.LfiEmulator", mock.Mock(), create=True):
            self.handler = base.BaseHandler("/tmp/", "test.db", self.loop)

        def mock_lfi_scan(value):
            return dict(name="lfi", order=0)

        self.handler.emulators["lfi"].scan = mock_lfi_scan
        self.detection = None

    def test_handle_sqli(self):
        data = dict(path="/index.html?id=1 UNION SELECT 1", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        async def mock_sqli_handle(path, session):
            return "sqli_test_payload"

        def mock_sqli_scan(value):
            return dict(name="sqli", order=2)

        self.handler.emulators["sqli"] = mock.Mock()
        self.handler.emulators["sqli"].handle = mock_sqli_handle
        self.handler.emulators["sqli"].scan = mock_sqli_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "sqli", "order": 2, "payload": "sqli_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_xss(self):
        data = dict(
            path="/index.html?id=<script>alert(1);</script>", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"}
        )

        async def mock_xss_handle(path, session):
            return "xss_test_payload"

        def mock_xss_scan(value):
            return dict(name="xss", order=3)

        self.handler.emulators["xss"] = mock.Mock()
        self.handler.emulators["xss"].handle = mock_xss_handle
        self.handler.emulators["xss"].scan = mock_xss_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "xss", "order": 3, "payload": "xss_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_lfi(self):
        data = dict(path="/index.html?file=/etc/passwd", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        async def mock_lfi_handle(attack_value, session):
            return "lfi_test_payload"

        def mock_lfi_scan(value):
            return dict(name="lfi", order=2)

        self.handler.emulators["lfi"] = mock.Mock()
        self.handler.emulators["lfi"].handle = mock_lfi_handle
        self.handler.emulators["lfi"].scan = mock_lfi_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "lfi", "order": 2, "payload": "lfi_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_index(self):
        data = dict(path="/index.html", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "index", "order": 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_wp_content(self):
        data = dict(path="/wp-content/", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "wp-content", "order": 1}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_rfi(self):
        data = dict(
            path="/index.html?file=http://attack.php", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"}
        )

        async def mock_rfi_handle(path, session):
            return "rfi_test_payload"

        def mock_rfi_scan(value):
            return dict(name="rfi", order=2)

        self.handler.emulators["rfi"] = mock.Mock()
        self.handler.emulators["rfi"].handle = mock_rfi_handle
        self.handler.emulators["rfi"].scan = mock_rfi_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "rfi", "order": 2, "payload": "rfi_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_php_object_injection(self):
        data = dict(
            path='/page.php?insert=\'O:15:"ObjectInjection":1:{s:6:"insert";s:2:"id";}\'',
            cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"},
        )

        async def mock_php_object_injection_handle(path, session):
            return "php_object_injection_test_payload"

        def mock_php_object_injection_scan(value):
            return dict(name="php_object_injection", order=3)

        self.handler.emulators["php_object_injection"] = mock.Mock()
        self.handler.emulators["php_object_injection"].handle = mock_php_object_injection_handle
        self.handler.emulators["php_object_injection"].scan = mock_php_object_injection_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "php_object_injection", "order": 3, "payload": "php_object_injection_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_xxe_injection(self):
        payload = (
            '<?xml version="1.0" encoding="ISO-8859-1"'
            "<!DOCTYPE foo [ <!ELEMENT foo ANY "
            '<!ENTITY xxe SYSTEM "file:///etc/passwd" ]'
        )

        data = dict(post_data={"submit": payload}, cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        async def mock_xxe_injection_handle(path, session):
            return "xxe_injection_test_payload"

        def mock_xxe_injection_scan(value):
            return dict(name="xxe_injection", order=3)

        self.handler.emulators["xxe_injection"] = mock.Mock()
        self.handler.emulators["xxe_injection"].handle = mock_xxe_injection_handle
        self.handler.emulators["xxe_injection"].scan = mock_xxe_injection_scan

        detection = self.loop.run_until_complete(self.handler.handle_post(self.session, data))

        assert_detection = {"name": "xxe_injection", "order": 3, "payload": "xxe_injection_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_handle_template_injection(self):
        data = dict(path="/index.php?p={{7*7}}", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        async def mock_template_injection_handle(path, session):
            return "template_injection_test_payload"

        def mock_template_injection_scan(value):
            return dict(name="template_injection", order=4)

        self.handler.emulators["template_injection"] = mock.Mock()
        self.handler.emulators["template_injection"].handle = mock_template_injection_handle
        self.handler.emulators["template_injection"].scan = mock_template_injection_scan

        detection = self.loop.run_until_complete(self.handler.handle_get(self.session, data))

        assert_detection = {"name": "template_injection", "order": 4, "payload": "template_injection_test_payload"}
        self.assertDictEqual(detection, assert_detection)

    def test_set_injectable_page(self):
        paths = [
            {"path": "/python.html", "timestamp": 1465851064.2740946},
            {"path": "/python.php/?foo=bar", "timestamp": 1465851065.2740946},
            {"path": "/python.html/?foo=bar", "timestamp": 1465851065.2740946},
        ]
        with mock.patch("tanner.sessions.session.Session") as mock_session:
            mock_session.return_value.paths = paths
            sess = session.Session(None)
        injectable_page = self.handler.set_injectable_page(sess)
        self.assertEqual(injectable_page, "/python.html")

    def test_emulate_type_1(self):
        data = dict(method="GET", path="/index.html", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"})

        self.handler.handle_get = AsyncMock(return_value={"name": "index", "order": 1})
        self.handler.set_injectable_page = mock.Mock()

        detection = self.loop.run_until_complete(self.handler.emulate(data, self.session))
        assert_detection = {"name": "index", "order": 1, "type": 1, "version": tanner_version}
        self.assertEqual(detection, assert_detection)
        assert not self.handler.set_injectable_page.called

    def test_emulate_type_2(self):
        self.handler.handle_get = AsyncMock(
            return_value={"name": "lfi", "order": 2, "payload": {"page": "/something.html"}}
        )

        data = dict(
            method="GET", path="/path.html?file=/etc/passwd", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"}
        )

        self.handler.set_injectable_page = mock.MagicMock(return_value="/path.html")

        async def test():
            self.detection = await self.handler.emulate(data, self.session)

        self.loop.run_until_complete(test())
        self.handler.set_injectable_page.assert_called_with(self.session)
        assert_detection = {
            "name": "lfi",
            "order": 2,
            "payload": {"page": "/path.html"},
            "type": 2,
            "version": tanner_version,
        }
        self.assertEqual(self.detection, assert_detection)

    def test_emulate_type_3(self):
        self.handler.handle_get = AsyncMock(
            return_value={"name": "php_code_injection", "order": 3, "payload": {"status_code": 504}}
        )

        data = dict(
            method="GET", path="/index.html?file=/etc/passwd", cookies={"sess_uuid": "9f82e5d0e6b64047bba996222d45e72c"}
        )
        self.handler.set_injectable_page = mock.Mock()

        detection = self.loop.run_until_complete(self.handler.emulate(data, self.session))
        assert_detection = {
            "name": "php_code_injection",
            "order": 3,
            "payload": {"status_code": 504},
            "type": 3,
            "version": tanner_version,
        }
        self.assertEqual(detection, assert_detection)
        assert not self.handler.set_injectable_page.called
