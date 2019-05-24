import unittest
import asyncio
from unittest import mock
from tanner.utils.asyncmock import AsyncMock
from tanner.emulators.mysqli import MySQLIEmulator


def mock_config(section, value):
    if section == 'SQLI' and value == 'host':
        return '127.0.0.1'
    if section == 'SQLI' and value == 'user':
        return 'root'
    if section == 'SQLI' and value == 'password':
        return ''


class TestMySQLi(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.db_name = 'test_db'

        self.handler = MySQLIEmulator(self.db_name)
        self.conn = None
        self.cursor = None
        self.attacker_db = None
        self.query_map = None
        self.expected_result = None
        self.returned_result = None

        with mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config) as m:
            async def connect():
                self.conn = await self.handler.helper.connect_to_db()
                self.cursor = await self.conn.cursor()

                self.returned_result = await self.handler.helper.check_db_exists(self.db_name)

                if self.returned_result == 1:
                    await self.handler.helper.delete_db(self.db_name)

                await self.cursor.execute('CREATE DATABASE test_db')
                await self.cursor.execute('USE {db_name}'.format(db_name='test_db'))
                await self.cursor.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, username TEXT)')
                await self.cursor.execute('INSERT INTO test VALUES(0, "test0")')
                await self.conn.commit()

            self.loop.run_until_complete(connect())

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_setup_db(self, m):
        self.expected_result = {'comments': [{'name': 'comment_id', 'type': 'INTEGER'}, ],
                                'users': [{'name': 'id', 'type': 'INTEGER'}, ]}

        self.handler.helper.create_query_map = AsyncMock(
            return_value={'comments': [{'name': 'comment_id', 'type': 'INTEGER'}, ],
                          'users': [{'name': 'id', 'type': 'INTEGER'}, ]})

        async def test():
            self.returned_result = await self.handler.setup_db()

        self.loop.run_until_complete(test())
        self.handler.helper.create_query_map.assert_called_with(self.db_name)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_create_attacker_db(self, m):
        session = mock.Mock()
        session.sess_uuid.hex = 'd877339ec415484987b279469167af3d'
        attacker_db = 'attacker_' + session.sess_uuid.hex
        self.handler.helper.copy_db = AsyncMock(return_value=attacker_db)

        async def test():
            self.attacker_db = await self.handler.create_attacker_db(session)

        self.loop.run_until_complete(test())
        self.handler.helper.copy_db.assert_called_with(self.db_name, attacker_db)

    @mock.patch('tanner.config.TannerConfig.get', side_effect=mock_config)
    def test_insert_dummy_data(self, m):

        def mock_generate_dummy_data(data_tokens):
            return [(1, 'test1'), (2, 'test2')], ['I', 'L']

        self.handler.helper.generate_dummy_data = mock_generate_dummy_data
        self.expected_result = ((0, 'test0'), (1, 'test1'), (2, 'test2'))

        async def test():
    
            await self.handler.helper.insert_dummy_data('test', 'I,L', self.cursor)
            await self.cursor.execute('SELECT * FROM test;')
            self.returned_result = await self.cursor.fetchall()

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)
