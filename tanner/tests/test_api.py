import pytest
import unittest
import asyncio
import aioredis
import itertools
import sqlalchemy
from unittest import mock
from aiopg.sa import create_engine
from tanner.api.api import Api
from tanner import postgres_client
from tanner.dbutils import DBUtils
from tanner.utils.asyncmock import AsyncMock

SESSION_DATA = {
    "sess_uuid": "ba800b95-28dd-4a78-b279-940781ce9513",
    "peer_ip": "196.207.97.20",
    "peer_port": 36864,
    "location": {
        "country": "India",
        "country_code": "IN",
        "city": "Delhi",
        "zip_code": "110092",
    },
    "user_agent": "Mozilla/5.0",
    "snare_uuid": "9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e",
    "start_time": 1589192688.001088,
    "end_time": 1589192688.7164452,
    "requests_in_second": 6.989514155656564,
    "approx_time_between_requests": 0.14308667182922363,
    "accepted_paths": 5,
    "errors": 0,
    "hidden_links": 0,
    "attack_types": ["index", "lfi", "cmd_exec"],
    "attack_count": {"index": 5},
    "paths": [
        {
            "path": "/sites/default/files",
            "timestamp": 1589192688.0010145,
            "response_status": 200,
            "attack_type": "index",
        },
        {
            "path": "/sites/default/../files",
            "timestamp": 1589192658.0010125,
            "response_status": 200,
            "attack_type": "lfi",
        },
        {
            "path": "/sites/default/;ls",
            "timestamp": 1589192618.0010145,
            "response_status": 200,
            "attack_type": "cmd_exec",
        },
    ],
    "cookies": {"sess_uuid": "d96bfa6d-e7a4-4344-99ab-c39cc448208f"},
    "referer": "/",
    "possible_owners": {"user": 1},
}


class TestApi(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.pg_client = None
        self.returned_content = None
        self.expected_content = None
        self.conn = None
        self.key = None

        async def create_db():
            async with create_engine(
                user="postgres", host="127.0.0.1", password="postgres"
            ) as engine:
                async with engine.acquire() as conn:
                    await conn.execute("CREATE DATABASE tanner_test_db")

        async def connect():
            self.postgres = postgres_client.PostgresClient()
            self.postgres.host = "localhost"
            self.postgres.post = 5432
            self.postgres.db_name = "tanner_test_db"
            self.postgres.user = "postgres"
            self.postgres.password = "postgres"
            self.postgres.maxsize = 80
            self.pg_client = await self.postgres.get_pg_client()
            await DBUtils.create_data_tables(self.pg_client)
            await DBUtils.add_analyzed_data(SESSION_DATA, self.pg_client)

        self.loop.run_until_complete(create_db())
        self.loop.run_until_complete(connect())
        self.handler = Api(self.pg_client)

    def test_return_snares(self):
        self.expected_content = SESSION_DATA["snare_uuid"]

        async def test():
            self.returned_content = await self.handler.return_snares()

        self.loop.run_until_complete(test())

        self.assertEqual(self.returned_content[0], self.expected_content)

    def test_return_snare_stats(self):
        self.expected_content = {
            "total_sessions": 1,
            "total_duration": "0:00:00",
            "attack_frequency": {"index": 1, "lfi": 1, "cmd_exec": 1},
        }

        async def test():
            self.returned_content = await self.handler.return_snare_stats(
                SESSION_DATA["snare_uuid"]
            )

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)

    def test_return_snare_info(self):
        offset = 0
        count = 1000

        async def test(snare_id):
            self.result = await self.handler.return_snare_info(snare_id, count, offset)

        self.loop.run_until_complete(test(SESSION_DATA["snare_uuid"]))
        self.assertEqual(len(self.result), 1)
        self.assertEqual(SESSION_DATA["sess_uuid"], self.result[0]["id"])
        self.assertEqual(
            SESSION_DATA["accepted_paths"], self.result[0]["accepted_paths"]
        )

    def test_return_snare_info_empty(self):
        offset = 1
        count = 1

        async def test(snare_id):
            self.result = await self.handler.return_snare_info(snare_id, count, offset)

        self.loop.run_until_complete(test(SESSION_DATA["snare_uuid"]))
        self.assertFalse(self.result)

    def test_return_snare_info_error(self):
        offset = 0
        count = 1000

        async def test(snare_id):
            self.result = await self.handler.return_snare_info(snare_id, count, offset)

        self.loop.run_until_complete(test("9f7d7dd3-ac6b-468b-8cee-"))
        self.assertIn("Invalid SNARE UUID", self.result)

    def test_return_session_info(self):
        self.uuid = SESSION_DATA["sess_uuid"]

        async def test():
            self.returned_data = await self.handler.return_session_info(self.uuid)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_content, self.expected_content)
        self.assertEqual(SESSION_DATA["sess_uuid"], self.returned_data["id"])
        self.assertEqual("Mozilla/5.0", self.returned_data["user_agent"])

    def test_return_session_info_error(self):
        async def test(sess_uuid):
            self.returned_content = await self.handler.return_session_info(sess_uuid)

        self.loop.run_until_complete(test("9f7d7dd3-ac6b-468b-8cee-"))
        self.assertIn("Invalid SESSION UUID", self.returned_content)

    def test_return_sessions(self):
        self.filters = {"sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"]}
        self.expected_content = [SESSION_DATA["sess_uuid"]]

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())

        self.assertEqual(self.expected_content, self.returned_content)

    def test_return_sessions_error(self):
        self.filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "attacktype": [6],
        }

        async def test():
            self.returned_content = await self.handler.return_sessions(self.filters)

        self.loop.run_until_complete(test())
        self.assertIn("Invalid filters", self.returned_content)

    def test_apply_filter_user_agent(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "user_agent": ["Mozilla/5.0"],
        }
        self.expected_content = (
            "SELECT S.id FROM sessions S WHERE "
            "S.sensor_id='9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e'"
            " AND S.user_agent='Mozilla/5.0'"
        )
        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(self.returned_content, self.expected_content)

    def test_apply_filter_possible_owner(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "owners": ["crawler"],
        }

        self.expected_content = (
            "SELECT S.id, O.session_id FROM sessions S, owners O "
            "WHERE S.sensor_id='9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e'"
            " AND O.owner_type='crawler' AND S.id=O.session_id"
        )
        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(self.returned_content, self.expected_content)

    def test_apply_filter_attack_types(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "attack_type": ["index"],
        }

        self.expected_content = (
            "SELECT S.id, P.session_id FROM sessions S, paths P "
            "WHERE S.sensor_id='9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e'"
            " AND P.attack_type=6 AND S.id=P.session_id"
        )

        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(self.expected_content, self.returned_content)

    def test_apply_filter_attack_type_invalid_value(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "attack_type": ["random"],
        }

        expected_error = "Invalid filter value"
        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(expected_error, self.returned_content)

    def test_apply_filter_start_time(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "start_time": ["11-05-2020"],
        }

        self.expected_content = (
            "SELECT S.id FROM sessions S WHERE "
            "S.sensor_id='9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e' "
            "AND S.start_time>='2020-05-11 00:00:00'"
        )

        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(self.returned_content, self.expected_content)

    def test_apply_filter_end_time(self):
        filters = {
            "sensor_id": ["9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e"],
            "end_time": ["11-05-2020"],
        }

        self.expected_content = (
            "SELECT S.id FROM sessions S WHERE "
            "S.sensor_id='9f7d7dd3-ac6b-468b-8cee-ce3e352eff6e' "
            "AND S.end_time<='2020-05-11 00:00:00'"
        )

        self.returned_content = self.handler.apply_filters(filters)
        self.assertEqual(self.returned_content, self.expected_content)

    def tearDown(self):
        async def close():
            async with self.pg_client.acquire() as conn:
                await conn.execute("DROP TABLE cookies;")
                await conn.execute("DROP TABLE owners;")
                await conn.execute("DROP TABLE paths;")
                await conn.execute("DROP TABLE sessions;")

            async with create_engine(
                user="postgres", host="127.0.0.1", password="postgres"
            ) as engine:

                async with engine.acquire() as conn:
                    await conn.execute(
                        "REVOKE CONNECT ON DATABASE tanner_test_db FROM public;"
                    )
                    await conn.execute(
                        """SELECT pg_terminate_backend(pg_stat_activity.pid)
                    FROM pg_stat_activity
                        WHERE pg_stat_activity.datname = 'tanner_test_db';
                    """
                    )
                    await conn.execute("DROP database tanner_test_db")

            self.pg_client.close()
            await self.pg_client.wait_closed()

        self.loop.run_until_complete(close())
