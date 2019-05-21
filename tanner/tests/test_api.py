import unittest
import asyncio
import aioredis
from unittest import mock
from tanner.api.api import Api
from tanner.utils.asyncmock import AsyncMock


class TestApi(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        redis = mock.Mock()
        self.redis_client = redis
        self.snare_uuid = "78e51180-bf0d-4757-8a04-f000e5efa179"
        self.uuid = "c546114f97f548f982756495f963e280"
        self.returned_content = None
        self.expected_content = None

    def test_return_snares(self):
        self.redis_client.smembers = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"])
        self.handler = Api(self.redis_client)
        self.expected_content = ["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"]

        async def test():
            self.returned_content = await self.handler.return_snares()

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_snares_error(self):
        self.redis_client.smembers = AsyncMock(side_effect=aioredis.ProtocolError)
        self.handler = Api(self.redis_client)

        async def test():
            self.returned_content = await self.handler.return_snares()

        with self.assertLogs(level='ERROR') as log:
            self.loop.run_until_complete(test())
            self.assertIn('Can not connect to redis', log.output[0])

    def test_return_snare_stats(self):
        self.handler = Api(self.redis_client)
        sessions = {
            "sess1": {
                "end_time": 2.00,
                "start_time": 0.00,
                "attack_types": ["lfi", "xss"]
            },
            "sess2": {
                "end_time": 4.00,
                "start_time": 2.00,
                "attack_types": ["rfi", "lfi", "cmd_exec"]
            }
        }
        self.handler.return_snare_info = AsyncMock(return_value=sessions)

        self.expected_content = {
            "attack_frequency": {
                'cmd_exec': 1, 'lfi': 2, 'rfi': 1, 'sqli': 0, 'xss': 1
            },
            'total_duration': 4.0, 'total_sessions': 2
        }

        async def test():
            self.returned_content = await self.handler.return_snare_stats(self.snare_uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_snare_info(self):
        query_res = ['{"sess1": {"end_time": 2.00, "start_time": 0.00 }, "sess2": {"attack_types": ["rfi"]}}']

        self.redis_client.zrevrangebyscore = AsyncMock(return_value=query_res)
        self.handler = Api(self.redis_client)
        self.expected_content = [{'sess1': {'end_time': 2.0, 'start_time': 0.0}, 'sess2': {'attack_types': ['rfi']}}]

        async def test():
            self.returned_content = await self.handler.return_snare_info(self.uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_content, self.returned_content)

    def test_return_snare_info_error(self):
        self.redis_client.zrevrangebyscore = AsyncMock(side_effect=aioredis.ProtocolError)
        self.handler = Api(self.redis_client)

        async def test():
            self.returned_content = await self.handler.return_snare_info(self.uuid)

        with self.assertLogs(level='ERROR') as log:
            self.loop.run_until_complete(test())
            self.assertIn('Can not connect to redis', log.output[0])

    def test_return_session_info(self):
        self.handler = Api(self.redis_client)

        sessions = {
            "sess1": {
                "sess_uuid": "c546114f97f548f982756495f963e280"
            },
            "sess2": {
                "sess_uuid": "f432785f97f548f98289054f963e972"
            }
        }
        self.handler.return_snare_info = AsyncMock(return_value=sessions)
        self.expected_content = 'sess1'

        async def test():
            self.returned_content = await self.handler.return_session_info(self.uuid, self.snare_uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_session_info_none(self):
        self.handler = Api(self.redis_client)

        self.handler.return_snares = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4",
                                                             "6ea6aw67-7821-4085-7u6t-q1io3p0i90b1"])

        async def mock_return_snare_info(snare_uuid):
            sessions = None
            if snare_uuid == "8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4":
                sessions = {
                    "sess1": {
                        "sess_uuid": "f432785f97f548f98289054f963e972"
                    }
                }

            if snare_uuid == "6ea6aw67-7821-4085-7u6t-q1io3p0i90b1":
                sessions = {
                    "sess2": {
                        "sess_uuid": "c546114f97f548f982756495f963e280"
                    }
                }
            return sessions

        self.handler.return_snare_info = mock_return_snare_info
        self.expected_content = "sess2"

        async def test():
            self.returned_content = await self.handler.return_session_info(self.uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_sessions(self):
        self.handler = Api(self.redis_client)
        self.handler.return_snares = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"])

        sessions = {
            "sess1": {
                'user_agent': "Mozilla/5.0",
                'peer_ip': "10.0.0.3"
            },
            "sess2": {
                'attack_types': ["lfi", "xss"],
                'possible_owners': ["crawler"],
                'start_time': 148580,
                'end_time': 148588,
                'snare_uuid': [self.snare_uuid]
            }
        }

        self.handler.return_snare_info = AsyncMock(return_value=sessions)
        self.filters = {
            'user_agent': "Mozilla",
            'peer_ip': "10.0.0.1",
            'attack_types': "xss",
            'possible_owners': "crawler",
            'start_time': 148575,
            'end_time': 148590,
            'snare_uuid': self.snare_uuid
        }

        self.handler.apply_filter = mock.Mock(return_value=True)
        self.expected_content = ["sess1", "sess2"]

        calls = [
            mock.call('user_agent', 'Mozilla', 'sess1'), mock.call('peer_ip', '10.0.0.1', 'sess1'),
            mock.call('attack_types', 'xss', 'sess2'), mock.call('possible_owners', 'crawler', 'sess2'),
            mock.call('start_time', 148575, 'sess2'), mock.call('end_time', 148590, 'sess2'),
            mock.call('snare_uuid', self.snare_uuid, 'sess2')
        ]

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())
        self.handler.apply_filter.assert_has_calls(calls, any_order=True)
        self.assertEqual(self.expected_content, self.returned_content)

    def test_return_sessions_error(self):
        self.handler = Api(self.redis_client)
        self.handler.return_snares = AsyncMock(return_value=["8fa6aa98-4283-4085-bfb9-a1cd3a9e56e4"])

        session = {
            "sess1": {
                "attack_types": ["rfi", "lfi"]
            }
        }
        self.handler.return_snare_info = AsyncMock(return_value=session)

        self.filters = {
            "attacktypes": "lfi"
        }

        self.expected_content = 'Invalid filter : attacktypes'

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_content, self.returned_content)

    def test_apply_filter_user_agent(self):
        self.handler = Api(self.redis_client)
        filter_name = 'user_agent'
        filter_value = 'Mozilla'

        session = {
            'user_agent': 'Mozilla/5.0'
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_user_agent_false(self):
        self.handler = Api(self.redis_client)
        filter_name = 'user_agent'
        filter_value = 'Mozilla Firefox'

        session = {
            'user_agent': 'Mozilla/5.0'
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_possible_owner(self):
        self.handler = Api(self.redis_client)
        filter_name = 'possible_owners'
        filter_value = 'crawler'

        session = {
            'possible_owners': ['user']
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_attack_types(self):
        self.handler = Api(self.redis_client)
        filter_name = 'attack_types'
        filter_value = "xss"

        session = {
            "attack_types": ["rfi", "xss"]
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_attack_types_false(self):
        self.handler = Api(self.redis_client)
        filter_name = 'attack_types'
        filter_value = "lfi"

        session = {
            "attack_types": ["rfi", "xss"]
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_start_time(self):
        self.handler = Api(self.redis_client)
        filter_name = 'start_time'
        filter_value = 148560

        session = {
            'start_time': 148570
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)

    def test_apply_filter_start_time_false(self):
        self.handler = Api(self.redis_client)
        filter_name = 'start_time'
        filter_value = 148560

        session = {
            'start_time': 148555
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)

    def test_apply_filter_end_time(self):
        self.handler = Api(self.redis_client)
        filter_name = 'end_time'
        filter_value = 148580

        session = {
            'end_time': 148565
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertTrue(self.returned_content)
    
    def test_apply_filter_end_time_false(self):
        self.handler = Api(self.redis_client)
        filter_name = 'end_time'
        filter_value = 148580

        session = {
            'end_time': 148590
        }

        self.returned_content = self.handler.apply_filter(filter_name, filter_value, session)
        self.assertFalse(self.returned_content)