import unittest
import asyncio
import aioredis
import itertools

from unittest import mock
from tanner.api.api import Api
from tanner import redis_client
from tanner.utils.asyncmock import AsyncMock


class TestApi(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.redis_client = None
        self.snare_uuid = "9a631aee-2b52-4108-9831-b495ac8afa80"
        self.uuid = "da1811cd19d748058bc02ee5bf9029d4"
        self.returned_content = None
        self.expected_content = None
        self.conn = None
        self.key = None

        async def connect():
            self.redis_client = await redis_client.RedisClient.get_redis_client()

        self.loop.run_until_complete(connect())
        self.handler = Api(self.redis_client)

    def test_return_snares(self):
        self.expected_content = ["9a631aee-2b52-4108-9831-b495ac8afa80", "8b901tyg-2b65-3428-9765-b431vhm4fu76"]
        self.key = b"snare_ids"

        async def setup():
            await self.redis_client.sadd(self.key, self.snare_uuid.encode())
            await self.redis_client.sadd(self.key, "8b901tyg-2b65-3428-9765-b431vhm4fu76".encode())

        async def test():
            self.returned_content = await self.handler.return_snares()

        self.loop.run_until_complete(setup())
        self.loop.run_until_complete(test())

        for id in self.returned_content:
            assert id in self.expected_content

    def test_return_snares_error(self):
        self.redis_client.smembers = mock.Mock(side_effect=aioredis.ConnectionError)

        async def test():
            self.returned_content = await self.handler.return_snares()

        with self.assertLogs(level="ERROR") as log:
            self.loop.run_until_complete(test())
            self.assertIn("Can not connect to redis", log.output[0])

    def test_return_snare_stats(self):
        sessions = [
            {"end_time": 2.00, "start_time": 0.00, "attack_types": ["lfi", "xss"]},
            {"end_time": 4.00, "start_time": 2.00, "attack_types": ["rfi", "lfi", "cmd_exec"]},
        ]
        self.handler.return_snare_info = AsyncMock(return_value=sessions)

        self.expected_content = {
            "attack_frequency": {"cmd_exec": 1, "lfi": 2, "rfi": 1, "sqli": 0, "xss": 1},
            "total_duration": 4.0,
            "total_sessions": 2,
        }

        async def test():
            self.returned_content = await self.handler.return_snare_stats(self.snare_uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_snare_info(self):
        self.member1 = ['{"end_time": 2.00, "start_time": 0.00 }', '{"attack_types": ["rfi"]}']
        self.keys = [self.snare_uuid.encode(), "4b901tyg-2b65-3428-9765-b431vhm4fu76".encode()]
        self.scores = [0, 2]
        self.pair1 = list(itertools.chain(*zip(self.scores, self.member1)))

        self.member2 = ['{"user_agent": "Mozilla", "peer_ip": "127.0.0.1"}']
        self.pair2 = list(itertools.chain(*zip(self.scores, self.member2)))
        self.returned_content = []

        self.expected_content = [
            [{"attack_types": ["rfi"]}, {"end_time": 2.0, "start_time": 0.0}],
            [{"user_agent": "Mozilla", "peer_ip": "127.0.0.1"}],
        ]

        async def setup():
            await self.redis_client.zadd(self.snare_uuid.encode(), *self.pair1)
            await self.redis_client.zadd("4b901tyg-2b65-3428-9765-b431vhm4fu76".encode(), *self.pair2)

        self.loop.run_until_complete(setup())

        async def test(id):
            result = await self.handler.return_snare_info(id, count=2)
            self.returned_content.append(result)

        for key in self.keys:
            self.loop.run_until_complete(test(key))

        self.assertEqual(self.expected_content, self.returned_content)

    def test_return_snare_info_error(self):
        self.redis_client.zrevrangebyscore = mock.Mock(side_effect=aioredis.ConnectionError)

        async def test():
            self.returned_content = await self.handler.return_snare_info(self.uuid)

        with self.assertLogs(level="ERROR") as log:
            self.loop.run_until_complete(test())
            self.assertIn("Can not connect to redis", log.output[0])

    def test_return_session_info(self):

        sessions = [
            {"sess_uuid": "c546114f97f548f982756495f963e280"},
            {"sess_uuid": "da1811cd19d748058bc02ee5bf9029d4"},
        ]

        self.handler.return_snare_info = AsyncMock(return_value=sessions)
        self.expected_content = {"sess_uuid": "da1811cd19d748058bc02ee5bf9029d4"}

        async def test():
            self.returned_content = await self.handler.return_session_info(self.uuid, self.snare_uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_session_info_none(self):
        self.handler.return_snares = AsyncMock(
            return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4", "6ea6aw67-7821-4085-7u6t-q1io3p0i90b1"]
        )

        async def mock_return_snare_info(snare_uuid):
            sessions = None
            if snare_uuid == "8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4":
                sessions = [{"sess_uuid": "da1811cd19d748058bc02ee5bf9029d4"}]

            if snare_uuid == "6ea6aw67-7821-4085-7u6t-q1io3p0i90b1":
                sessions = [{"sess_uuid": "c546114f97f548f982756495f963e280"}]
            return sessions

        self.handler.return_snare_info = mock_return_snare_info
        self.expected_content = {"sess_uuid": "da1811cd19d748058bc02ee5bf9029d4"}

        async def test():
            self.returned_content = await self.handler.return_session_info(self.uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_sessions(self):
        self.handler.return_snares = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"])

        sessions = [
            {"user_agent": "Mozilla/5.0", "peer_ip": "10.0.0.3"},
            {
                "attack_types": ["lfi", "xss"],
                "possible_owners": ["crawler"],
                "start_time": 148580,
                "end_time": 148588,
                "snare_uuid": [self.snare_uuid],
            },
        ]

        self.handler.return_snare_info = AsyncMock(return_value=sessions)
        self.filters = {
            "user_agent": "Mozilla",
            "peer_ip": "10.0.0.1",
            "attack_types": "xss",
            "possible_owners": "crawler",
            "start_time": 148575,
            "end_time": 148590,
            "snare_uuid": self.snare_uuid,
        }

        self.handler.apply_filter = mock.Mock()

        def mock_result(filter_name, filter_value, sess):

            if sess == {"user_agent": "Mozilla/5.0", "peer_ip": "10.0.0.3"}:
                return True
            else:
                return False

        self.handler.apply_filter.side_effect = mock_result

        self.expected_content = [{"user_agent": "Mozilla/5.0", "peer_ip": "10.0.0.3"}]

        calls = [
            mock.call("user_agent", "Mozilla", {"user_agent": "Mozilla/5.0", "peer_ip": "10.0.0.3"}),
            mock.call(
                "attack_types",
                "xss",
                {
                    "attack_types": ["lfi", "xss"],
                    "possible_owners": ["crawler"],
                    "start_time": 148580,
                    "end_time": 148588,
                    "snare_uuid": [self.snare_uuid],
                },
            ),
        ]

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())

        self.handler.apply_filter.assert_has_calls(calls, any_order=True)
        self.assertEqual(self.expected_content, self.returned_content)

    def test_return_sessions_error(self):
        self.handler.return_snares = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"])

        session = [{"attack_types": ["rfi", "lfi"]}]
        self.handler.return_snare_info = AsyncMock(return_value=session)

        self.filters = {"attacktypes": "lfi"}

        self.expected_content = "Invalid filter : attacktypes"

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_content, self.returned_content)

    def test_apply_filter_user_agent(self):
        filter_name = "user_agent"
        filter_value = "Mozilla"

        session = {"user_agent": "Mozilla/5.0"}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_user_agent_false(self):
        filter_name = "user_agent"
        filter_value = "Mozilla Firefox"

        session = {"user_agent": "Mozilla/5.0"}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_possible_owner(self):
        filter_name = "possible_owners"
        filter_value = "crawler"

        session = {"possible_owners": ["user"]}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_attack_types(self):
        filter_name = "attack_types"
        filter_value = "xss"

        session = {"attack_types": ["rfi", "xss"]}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_attack_types_false(self):
        filter_name = "attack_types"
        filter_value = "lfi"

        session = {"attack_types": ["rfi", "xss"]}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_start_time(self):
        filter_name = "start_time"
        filter_value = 148560

        session = {"start_time": 148570}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_start_time_false(self):
        filter_name = "start_time"
        filter_value = 148560

        session = {"start_time": 148555}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_end_time(self):
        filter_name = "end_time"
        filter_value = 148580

        session = {"end_time": 148565}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_end_time_false(self):
        filter_name = "end_time"
        filter_value = 148580

        session = {"end_time": 148590}

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def tearDown(self):
        async def close():
            await self.redis_client.flushall()
            await self.redis_client.close()

        self.loop.run_until_complete(close())
