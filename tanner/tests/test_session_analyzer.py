import asyncio
import json
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import geoip2
import aioredis
from tanner.sessions.session_analyzer import SessionAnalyzer


session = (
    b'{"sess_uuid": "c546114f97f548f982756495f963e280", "start_time": 1466091813.4780173, '
    b'"referer": "/",'
    b'"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
    b'Chrome/53.0.2767.4 Safari/537.36", "end_time": 1466091899.9854035, '
    b'"snare_uuid": "78e51180-bf0d-4757-8a04-f000e5efa179", "count": 24, '
    b'"paths": [{"timestamp": 1466091813.4779778, "path": "/", "attack_type": "index", "response_status": 200},'
    b'{"timestamp": 1466091842.7088752, "path": "/fluent-python.html", "attack_type": "index", '
    b'"response_status": 200}, {"timestamp": 1466091858.214475, "path": "/wow-movie.html?exec=/bin/bash", '
    b'"attack_type": "index", "response_status": 200}, {"timestamp": 1466091871.9076045, '
    b'"path": "/wow-movie.html?exec=/etc/passwd", "attack_type": "lfi", "response_status": 200},'
    b'{"timestamp": 1466091885.1003792, "path": "/wow-movie.html?exec=/bin/bash", "attack_type": "index", '
    b'"response_status": 200}, {"timestamp": 1466091899.9854052, '
    b'"path": "/wow-movie.html?exec=/../../../..///././././.../../../etc/passwd",'
    b' "attack_type": "lfi", "response_status": 200}], '
    b'"peer": {"port": 56970, "ip": "74.217.37.84"}, '
    b'"cookies": {"sess_uuid": "c546114f97f548f982756495f963e280"}}'
)


def mock_open():
    with open("./tanner/data/crawler_user_agents.txt") as f:
        f.close = Mock()
        return Mock(return_value=f)


class TestSessionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.session = json.loads(session.decode("utf-8"))
        self.handler = SessionAnalyzer(loop=self.loop)
        self.res = None
        geoip2.database.Reader.__init__ = Mock(return_value=None)
        rvalue = geoip2.models.City(
            {
                "city": {"geoname_id": 4223379, "names": {"en": "Smyrna", "ru": "Смирна", "zh-CN": "士麦那"}},
                "continent": {
                    "code": "NA",
                    "geoname_id": 6255149,
                    "names": {
                        "de": "Nordamerika",
                        "en": "North America",
                        "es": "Norteamérica",
                        "fr": "Amérique du Nord",
                        "ja": "北アメリカ",
                        "pt-BR": "América do Norte",
                        "ru": "Северная Америка",
                        "zh-CN": "北美洲",
                    },
                },
                "country": {
                    "geoname_id": 6252001,
                    "iso_code": "US",
                    "names": {
                        "de": "USA",
                        "en": "United States",
                        "es": "Estados Unidos",
                        "fr": "États-Unis",
                        "ja": "アメリカ合衆国",
                        "pt-BR": "Estados Unidos",
                        "ru": "США",
                        "zh-CN": "美国",
                    },
                },
                "location": {
                    "accuracy_radius": 10,
                    "latitude": 33.8633,
                    "longitude": -84.4984,
                    "metro_code": 524,
                    "time_zone": "America/New_York",
                },
                "postal": {"code": "30080"},
                "registered_country": {
                    "geoname_id": 6252001,
                    "iso_code": "US",
                    "names": {
                        "de": "USA",
                        "en": "United States",
                        "es": "Estados Unidos",
                        "fr": "États-Unis",
                        "ja": "アメリカ合衆国",
                        "pt-BR": "Estados Unidos",
                        "ru": "США",
                        "zh-CN": "美国",
                    },
                },
                "subdivisions": [
                    {
                        "geoname_id": 4197000,
                        "iso_code": "GA",
                        "names": {
                            "en": "Georgia",
                            "es": "Georgia",
                            "fr": "Géorgie",
                            "ja": "ジョージア州",
                            "pt-BR": "Geórgia",
                            "ru": "Джорджия",
                            "zh-CN": "乔治亚",
                        },
                    }
                ],
                "traits": {"ip_address": "74.217.37.8"},
            },
            ["en"],
        )
        geoip2.database.Reader.city = Mock(return_value=rvalue)

    def tests_load_session_fail(self):
        async def sess_get(key):
            return aioredis.ConnectionError

        redis_mock = Mock()
        redis_mock.get = sess_get
        res = None
        with self.assertLogs():
            self.loop.run_until_complete(self.handler.analyze(None, redis_mock))

    def test_create_stats(self):
        async def sess_get():
            return session

        async def set_of_members(key):
            return set()

        async def set_add():
            return ""

        redis_mock = Mock()
        redis_mock.get = sess_get
        redis_mock.smembers = set_of_members
        redis_mock.zadd = set_add
        with patch("builtins.open", new_callable=mock_open) as m:
            stats = self.loop.run_until_complete(self.handler.create_stats(self.session, redis_mock))
        self.assertEqual(stats["possible_owners"], {"attacker": 1.0})

    def test_choose_owner_crawler(self):
        stats = dict(
            paths=[{"path": "/robots.txt", "timestamp": 1.0, "response_status": 200, "attack_type": "index"}],
            attack_types={"index"},
            requests_in_second=11.1,
            referer=None,
            peer_ip="ip",
        )

        async def test():
            self.res = await self.handler.choose_possible_owner(stats)

        with patch("builtins.open", new_callable=mock_open) as m:
            self.loop.run_until_complete(test())
        self.assertEqual(self.res["possible_owners"], {"crawler": 1.0})

    def test_choose_owner_attacker(self):
        stats = dict(
            paths=[{"path": "/", "timestamp": 1.0, "response_status": 200, "attack_type": "rfi"}],
            attack_types={"rfi", "lfi"},
            requests_in_second=2,
            user_agent="user",
            peer_ip="ip",
        )

        async def test():
            self.res = await self.handler.choose_possible_owner(stats)

        with patch("builtins.open", new_callable=mock_open) as m:
            self.loop.run_until_complete(test())
        self.assertEqual(self.res["possible_owners"], {"attacker": 1.0})

    def test_choose_owner_mixed(self):
        stats = dict(
            paths=[{"path": "/", "timestamp": 1.0, "response_status": 200, "attack_type": ""}],
            attack_types="",
            requests_in_second=2,
            user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            peer_ip="74.217.37.84",
            hidden_links=0,
            referer="/",
        )

        async def test():
            self.res = await self.handler.choose_possible_owner(stats)

        with patch("builtins.open", new_callable=mock_open) as m:
            self.loop.run_until_complete(test())
        self.assertEqual(self.res["possible_owners"], {"attacker": 0.75, "crawler": 0.25, "tool": 0.15, "user": 0.25})

    def test_choose_owner_user(self):
        stats = dict(
            paths=[{"path": "/", "timestamp": 1.0, "response_status": 200, "attack_type": ""}],
            attack_types="",
            requests_in_second=2,
            user_agent="test_user_agent",
            peer_ip="74.217.37.84",
            hidden_links=0,
            referer="/",
        )

        async def test():
            self.res = await self.handler.choose_possible_owner(stats)

        with patch("builtins.open", new_callable=mock_open) as m:
            self.loop.run_until_complete(test())
        self.assertEqual(self.res["possible_owners"], {"user": 1.0})

    def test_find_location(self):
        location_stats = self.handler.find_location("74.217.37.84")
        expected_res = dict(
            country="United States",
            country_code="US",
            city="Smyrna",
            zip_code="30080",
        )
        self.assertEqual(location_stats, expected_res)
