import unittest
import asyncio
import os
from unittest import mock
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
        self.query_map = None
        self.handler = MySQLDBHelper()

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_check_db_exists(self, m):
        self.expected_result = 0

        async def test():
            self.returned_result = await self.handler.check_db_exists(self.db_name)

        self.loop.run_until_complete(test())

        if self.returned_result == 1:
            async def delete():
                await self.handler.delete_db(self.db_name)
            self.loop.run_until_complete(delete())
        else:
            self.assertEqual(self.expected_result, self.returned_result)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_create_query_map(self, m):

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
        self.expected_result = {'TEST': [{'name': 'ID', 'type': 'INTEGER'},
                                         {'name': 'USERNAME', 'type': 'TEXT'}]}

        async def test():
            await self.handler.setup_db_from_config(self.db_name)
            self.query_map = await self.handler.create_query_map(self.db_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.query_map, self.expected_result)
