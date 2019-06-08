import unittest
import asyncio
import aioredis
from unittest import mock
from tanner import redis_client
from tanner import config
from tanner.utils.asyncmock import AsyncMock
from tanner.dorks_manager import DorksManager


class TestDorksManager(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.redis_client = None
        self.path = None

        async def connect():
            self.redis_client = await redis_client.RedisClient.get_redis_client()

        self.loop.run_until_complete(connect())

        self.handler = DorksManager()
        self.returned_result = None
        self.expected_result = None

    def test_push_init_dorks(self):
        self.redis_client.sadd = AsyncMock()

        async def test():
            await self.handler.push_init_dorks(config.TannerConfig.get('DATA', 'dorks'), self.handler.dorks_key,
                                               self.redis_client)

        self.loop.run_until_complete(test())
        assert self.redis_client.sadd.called

    def test_extract_path(self):
        self.path = 'http://example.com/index.html?page=26'

        async def test():
            await self.handler.extract_path(self.path, self.redis_client)
            self.returned_result = await self.redis_client.smembers(self.handler.user_dorks_key)

        self.loop.run_until_complete(test())
        self.expected_result = [b'http://example.com/index.html?page=']
        self.assertEqual(self.returned_result, self.expected_result)

    def test_extract_path_error(self):
        self.path = '/index.html?page=26'
        self.redis_client.sadd = AsyncMock(side_effect=aioredis.ProtocolError)

        async def test():
            await self.handler.extract_path(self.path, self.redis_client)

        with self.assertLogs(level='ERROR') as log:
            self.loop.run_until_complete(test())
            self.assertIn('Problem with redis connection', log.output[0])

    def test_init_dorks(self):
        self.handler.push_init_dorks = AsyncMock()

        calls = [
            mock.call(config.TannerConfig.get('DATA', 'dorks'), mock.ANY, self.redis_client),
            mock.call(config.TannerConfig.get('DATA', 'user_dorks'), mock.ANY, self.redis_client)
        ]

        async def test():
            await self.handler.init_dorks(self.redis_client)

        self.loop.run_until_complete(test())
        self.handler.push_init_dorks.assert_has_calls(calls)

    def tearDown(self):

        async def close():
            await self.redis_client.flushall()
            self.redis_client.close()
            await self.redis_client.wait_closed()

        self.loop.run_until_complete(close())
