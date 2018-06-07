import asyncio
import json
import unittest
from unittest.mock import Mock
from geoip2.database import Reader
import asyncio_redis

from tanner.session_analyzer import SessionAnalyzer

session = b'{"sess_uuid": "c546114f97f548f982756495f963e280", "start_time": 1466091813.4780173, ' \
          b'"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
          b'Chrome/53.0.2767.4 Safari/537.36", "end_time": 1466091899.9854035, ' \
          b'"snare_uuid": "78e51180-bf0d-4757-8a04-f000e5efa179", "count": 24, ' \
          b'"paths": [{"timestamp": 1466091813.4779778, "path": "/", "attack_type": "index", "response_status": 200},' \
          b'{"timestamp": 1466091842.7088752, "path": "/fluent-python.html", "attack_type": "index", ' \
          b'"response_status": 200}, {"timestamp": 1466091858.214475, "path": "/wow-movie.html?exec=/bin/bash", ' \
          b'"attack_type": "index", "response_status": 200}, {"timestamp": 1466091871.9076045, ' \
          b'"path": "/wow-movie.html?exec=/etc/passwd", "attack_type": "lfi", "response_status": 200},' \
          b'{"timestamp": 1466091885.1003792, "path": "/wow-movie.html?exec=/bin/bash", "attack_type": "index", ' \
          b'"response_status": 200}, {"timestamp": 1466091899.9854052, ' \
          b'"path": "/wow-movie.html?exec=/../../../..///././././.../../../etc/passwd",' \
          b' "attack_type": "lfi", "response_status": 200}], ' \
          b'"peer": {"port": 56970, "ip": "74.217.37.84"}, ' \
          b'"cookies": {"sess_uuid": "c546114f97f548f982756495f963e280"}}'


class TestSessionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.session = json.loads(session.decode('utf-8'))
        self.handler = SessionAnalyzer(loop=self.loop)
        response = Mock()
        response.country.name = 'United States'
        response.country.iso_code = 'US'
        response.city.name = 'Smyrna'
        response.postal.code = '30080'
        Reader.city = Mock(return_value=response)

    def tests_load_session_fail(self):
        async def sess_get(key):
            return asyncio_redis.NotConnectedError

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

        async def push_list():
            return ''

        redis_mock = Mock()
        redis_mock.get = sess_get
        redis_mock.smembers_asset = set_of_members
        redis_mock.lpush = push_list
        stats = self.loop.run_until_complete(self.handler.create_stats(self.session, redis_mock))
        self.assertEqual(stats['possible_owners'], ['attacker'])

    def test_find_location_result(self):
        async def sess_get():
            return session

        async def set_of_members(key):
            return set()

        async def push_list():
            return ''
        redis_mock = Mock()
        redis_mock.get = sess_get
        redis_mock.smembers_asset = set_of_members
        redis_mock.lpush = push_list
        stats = self.loop.run_until_complete(self.handler.create_stats(self.session, redis_mock))
        expected_res = dict(
            country='United States',
            country_code='US',
            city='Smyrna',
            zip_code='30080',
        )
        self.assertEqual(stats['location'], expected_res)

    def test_find_location_call(self):
        async def sess_get():
            return session

        async def set_of_members(key):
            return set()

        async def push_list():
            return ''
        redis_mock = Mock()
        redis_mock.get = sess_get
        redis_mock.smembers_asset = set_of_members
        redis_mock.lpush = push_list
        self.loop.run_until_complete(self.handler.create_stats(self.session, redis_mock))
        Reader.city.assert_called_with('74.217.37.84')
