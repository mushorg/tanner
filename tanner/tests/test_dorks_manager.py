import unittest
import asyncio
import aioredis
import random
import pickle
import os
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

        # Creating pickle files
        self.dorks_pickle = "/tmp/test.pickle"
        data = "file.php?q=par index.php?qry=param index.php/image?p=rs"
        dbfile = open(self.dorks_pickle, "wb")
        pickle.dump(data, dbfile)

        self.user_dorks_pickle = "/tmp/user_dorks.pickle"
        db = open(self.user_dorks_pickle, "wb")
        data = "file1.php?q=ar index.php?q=p index.php/image2?p=r"
        pickle.dump(data, db)

        self.handler = DorksManager()
        self.returned_result = None
        self.expected_result = None

    def test_push_init_dorks(self):
        self.expected_result = ["index.php/image?p=rs", "index.php?qry=param", "file.php?q=par"]

        async def setup():
            await self.handler.push_init_dorks(self.dorks_pickle, self.handler.dorks_key, self.redis_client)

        async def test():
            self.returned_result = await self.redis_client.smembers(self.handler.dorks_key)

        self.loop.run_until_complete(setup())
        self.loop.run_until_complete(test())
        for data in self.returned_result:
            assert data in self.expected_result

    def test_extract_path(self):
        self.path = "http://example.com/index.html?page=26"

        async def test():
            await self.handler.extract_path(self.path, self.redis_client)
            self.returned_result = await self.redis_client.smembers(self.handler.user_dorks_key)

        self.loop.run_until_complete(test())
        self.expected_result = {"http://example.com/index.html?page="}
        self.assertEqual(self.returned_result, self.expected_result)

    def test_extract_path_error(self):
        self.path = "/index.html?page=26"
        self.redis_client.sadd = AsyncMock(side_effect=aioredis.ConnectionError)

        async def test():
            await self.handler.extract_path(self.path, self.redis_client)

        with self.assertLogs(level="ERROR") as log:
            self.loop.run_until_complete(test())
            self.assertIn("Problem with redis connection", log.output[0])

    def test_init_dorks(self):
        self.handler.push_init_dorks = AsyncMock()

        calls = [
            mock.call(config.TannerConfig.get("DATA", "dorks"), mock.ANY, self.redis_client),
            mock.call(config.TannerConfig.get("DATA", "user_dorks"), mock.ANY, self.redis_client),
        ]

        async def test():
            await self.handler.init_dorks(self.redis_client)

        self.loop.run_until_complete(test())
        self.handler.push_init_dorks.assert_has_calls(calls)

    def test_init_dorks_none(self):
        self.handler.dorks_key = None
        self.handler.user_dorks_key = None
        self.handler.push_init_dorks = AsyncMock()

        async def test():
            await self.handler.init_dorks(self.redis_client)

        self.loop.run_until_complete(test())
        self.handler.push_init_dorks.assert_not_called()

    def test_choose_dorks(self):
        self.handler.init_dorks = AsyncMock()
        random.randint = mock.Mock(return_value=3)
        self.handler.init_done = False

        self.expected_result = [
            "index.php/image?p=rs",
            "file.php?q=par",
            "index.php?qry=param",
            "index.php?q=p",
            "file1.php?q=ar",
            "index.php/image2?p=r",
        ]

        async def setup():
            await self.handler.push_init_dorks(self.dorks_pickle, self.handler.dorks_key, self.redis_client)
            await self.handler.push_init_dorks(self.user_dorks_pickle, self.handler.user_dorks_key, self.redis_client)

        self.loop.run_until_complete(setup())

        async def test():
            self.returned_result = await self.handler.choose_dorks(self.redis_client)

        self.loop.run_until_complete(test())
        self.handler.init_dorks.assert_called()
        for data in self.returned_result:
            assert data in self.expected_result

    def tearDown(self):
        async def close():
            os.remove(self.dorks_pickle)
            os.remove(self.user_dorks_pickle)
            await self.redis_client.flushall()
            await self.redis_client.close()

        self.loop.run_until_complete(close())
