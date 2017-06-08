import asyncio
import json
import unittest
from unittest import mock

import asyncio_redis

from tanner.session_analyzer import SessionAnalyzer

session = b'{"sess_uuid": "c546114f97f548f982756495f963e280", "start_time": 1466091813.4780173, ' \
          b'"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
          b'Chrome/53.0.2767.4 Safari/537.36", "end_time": 1466091899.9854035, ' \
          b'"sensor": "78e51180-bf0d-4757-8a04-f000e5efa179", "count": 24, ' \
          b'"paths": [{"timestamp": 1466091813.4779778, "path": "/", "attack_type": "index", "response_status": 200},' \
          b'{"timestamp": 1466091842.7088752, "path": "/fluent-python.html", "attack_type": "index", ' \
          b'"response_status": 200}, {"timestamp": 1466091858.214475, "path": "/wow-movie.html?exec=/bin/bash", ' \
          b'"attack_type": "index", "response_status": 200}, {"timestamp": 1466091871.9076045, ' \
          b'"path": "/wow-movie.html?exec=/etc/passwd", "attack_type": "lfi", "response_status": 200},' \
          b'{"timestamp": 1466091885.1003792, "path": "/wow-movie.html?exec=/bin/bash", "attack_type": "index", ' \
          b'"response_status": 200}, {"timestamp": 1466091899.9854052, ' \
          b'"path": "/wow-movie.html?exec=/../../../..///././././.../../../etc/passwd",' \
          b' "attack_type": "lfi", "response_status": 200}], ' \
          b'"peer": {"port": 56970, "ip": "192.168.1.3"}, ' \
          b'"cookies": {"sess_uuid": "c546114f97f548f982756495f963e280"}}'


class TestSessionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.session = json.loads(session.decode('utf-8'))
        self.handler = SessionAnalyzer(loop=self.loop)

    def tests_load_session_fail(self):
        async def sess_get(key):
            return asyncio_redis.NotConnectedError

        redis_mock = mock.Mock()
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

        redis_mock = mock.Mock()
        redis_mock.get = sess_get
        redis_mock.smembers_asset = set_of_members
        redis_mock.lpush = push_list
        stats = self.loop.run_until_complete(self.handler.create_stats(self.session, redis_mock))
        self.assertEqual(stats['possible_owners'], ['attacker'])
