import unittest
import asyncio
import os
from unittest import mock
from tanner.utils.asyncmock import AsyncMock
from tanner.utils.mysql_db_helper import MySQLDBHelper


def mock_config(section, value):
    if section == 'SQLI' and value == 'host':
        return '127.0.0.1'
    if section == 'SQLI' and value == 'user':
        return 'root'
    if section == 'SQLI' and value == 'password':
        return ''


class TestMySQLDBHelper(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.filename = '/tmp/db/test_db'
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open('/tmp/db/test_db', 'a').close()

        self.db_name = 'test_db'
        self.expected_result = None
        self.returned_result = None
        self.result = 0
        self.query_map = []
        self.handler = MySQLDBHelper()
        self.conn = None
        self.cursor = None

        with mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config) as m:
            async def connect():
                self.conn = await self.handler.connect_to_db()
                self.cursor = await self.conn.cursor()

                # Delete DB if exists
                self.returned_result = await self.handler.check_db_exists(self.db_name)
                if self.returned_result == 1:
                    await self.handler.delete_db(self.db_name)

            self.loop.run_until_complete(connect())

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_check_db_exists(self, m):
        self.expected_result = 1

        async def test():
            await self.cursor.execute('CREATE DATABASE test_db')
            await self.conn.commit()
            self.returned_result = await self.handler.check_db_exists(self.db_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_result, self.returned_result)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_check_no_db_exists(self, m):
        self.expected_result = 0

        async def test():
            self.returned_result = await self.handler.check_db_exists(self.db_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_result, self.returned_result)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_setup_db_from_config(self, m):
        config = {
            "name": "test_db",
            "tables": [
                {
                    "schema": "CREATE TABLE TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)",
                    "table_name": "TEST",
                    "data_tokens": "I,L"
                }
            ]
        }

        def mock_read_config():
            return config

        self.handler.read_config = mock_read_config
        self.handler.insert_dummy_data = AsyncMock()

        async def test():
            await self.handler.setup_db_from_config()

        self.loop.run_until_complete(test())
        assert self.handler.insert_dummy_data.called

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_copy_db(self, m):
        self.expected_result = 1

        async def test():
            self.returned_result = await self.handler.copy_db(self.db_name, "attacker_db")
            self.result = await self.handler.check_db_exists("attacker_db")

        self.loop.run_until_complete(test())
        self.assertEqual(self.result, self.expected_result)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_create_query_map(self, m):

        self.expected_result_creds = {'COMMON': [{'name': 'NUM', 'type': 'INTEGER'}],
                                      'CREDS': [{'name': 'ID', 'type': 'INTEGER'}, {'name': 'EMAIL', 'type': 'TEXT'},
                                                {'name': 'PASSWORD', 'type': 'TEXT'}]}

        self.expected_result_test = {'COMMON': [{'name': 'PARA', 'type': 'TEXT'}],
                                     'TEST': [{'name': 'ID', 'type': 'INTEGER'},
                                              {'name': 'USERNAME', 'type': 'TEXT'}]}

        self.query = [
            ['TEST_DB', "CREATE TABLE TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)", "CREATE TABLE COMMON (PARA TEXT)"],
            ['CREDS_DB', "CREATE TABLE CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), PASSWORD VARCHAR(15))",
             'CREATE TABLE COMMON (NUM INTEGER )']
        ]

        async def test(data):
            await self.cursor.execute('CREATE DATABASE {db_name}'.format(db_name=data[0]))
            await self.cursor.execute('USE {db_name}'.format(db_name=data[0]))
            await self.cursor.execute(data[1])
            await self.cursor.execute(data[2])
            result = await self.handler.create_query_map(data[0])
            self.query_map.append(result)
            await self.handler.delete_db(data[0])

        for data in self.query:
            self.loop.run_until_complete(test(data))

        self.assertEqual(self.query_map[0], self.expected_result_test)
        self.assertEqual(self.query_map[1], self.expected_result_creds)
