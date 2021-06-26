import unittest
import asyncio
from unittest import mock
from tanner.utils.asyncmock import AsyncMock
from tanner.emulators.mysqli import MySQLIEmulator


def mock_config(section, value):
    config = {"host": "127.0.0.1", "user": "root", "password": "user_pass"}

    return config[value]


class TestMySQLi(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.db_name = "test_db"

        self.handler = MySQLIEmulator(self.db_name)
        self.conn = None
        self.cursor = None
        self.attacker_db = None
        self.query_map = None
        self.expected_result = None
        self.returned_result = None

        async def connect():
            self.conn = await self.handler.helper.connect_to_db()
            self.cursor = await self.conn.cursor()

            self.returned_result = await self.handler.helper.check_db_exists(self.db_name)

            if self.returned_result == 1:
                await self.handler.helper.delete_db(self.db_name)

            await self.cursor.execute("CREATE DATABASE test_db")
            await self.cursor.execute("USE {db_name}".format(db_name="test_db"))
            await self.cursor.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, username TEXT)")
            await self.cursor.execute('INSERT INTO test VALUES(0, "test0")')
            await self.conn.commit()

        self.loop.run_until_complete(connect())

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_setup_db(self, m):
        self.expected_result = {
            "comments": [
                {"name": "comment_id", "type": "INTEGER"},
            ],
            "users": [
                {"name": "id", "type": "INTEGER"},
            ],
        }

        self.handler.helper.create_query_map = AsyncMock(
            return_value={
                "comments": [
                    {"name": "comment_id", "type": "INTEGER"},
                ],
                "users": [
                    {"name": "id", "type": "INTEGER"},
                ],
            }
        )

        self.handler.helper = AsyncMock()

        async def test():
            self.returned_result = await self.handler.setup_db()

        self.loop.run_until_complete(test())
        self.handler.helper.create_query_map.assert_called_with(self.db_name)
        assert not self.handler.helper.setup_db_from_config.called

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_setup_db_not_exists(self, m):
        self.expected_result = {
            "comments": [
                {"name": "comment_id", "type": "INTEGER"},
            ],
            "users": [
                {"name": "id", "type": "INTEGER"},
            ],
        }

        self.handler.helper.create_query_map = AsyncMock(
            return_value={
                "comments": [
                    {"name": "comment_id", "type": "INTEGER"},
                ],
                "users": [
                    {"name": "id", "type": "INTEGER"},
                ],
            }
        )
        self.handler.helper.setup_db_from_config = AsyncMock()

        async def test():
            await self.handler.helper.delete_db(self.db_name)
            self.returned_result = await self.handler.setup_db()

        self.loop.run_until_complete(test())
        self.handler.helper.setup_db_from_config.assert_called_with(self.db_name)
        self.handler.helper.create_query_map.assert_called_with(self.db_name)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_create_attacker_db(self, m):
        session = mock.Mock()
        session.sess_uuid.hex = "d877339ec415484987b279469167af3d"
        attacker_db = "attacker_" + session.sess_uuid.hex
        self.handler.helper.copy_db = AsyncMock(return_value=attacker_db)
        self.expected_result = "attacker_d877339ec415484987b279469167af3d"

        async def test():
            self.returned_result = await self.handler.create_attacker_db(session)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)
        session.associate_db.assert_called_with(attacker_db)
        self.handler.helper.copy_db.assert_called_with(self.db_name, attacker_db)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_execute_query(self, m):

        self.expected_result = [[[0, "test_name"]], [[0, "test@domain.com", "test_pass"]]]

        result = []
        self.query = [
            [
                "TEST_DB",
                "CREATE TABLE TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)",
                'INSERT INTO TEST VALUES(0, "test_name")',
            ],
            [
                "CREDS_DB",
                "CREATE TABLE CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), PASSWORD VARCHAR(15))",
                'INSERT INTO CREDS VALUES(0, "test@domain.com", "test_pass")',
            ],
        ]
        test_query = [["TEST_DB", "SELECT * FROM TEST"], ["CREDS_DB", "SELECT * FROM CREDS"]]

        async def setup(data):
            await self.cursor.execute("CREATE DATABASE {db_name}".format(db_name=data[0]))
            await self.cursor.execute("USE {db_name}".format(db_name=data[0]))
            await self.cursor.execute(data[1])
            await self.cursor.execute(data[2])
            await self.conn.commit()

        for data in self.query:
            self.loop.run_until_complete(setup(data))

        async def test(data):
            self.returned_result = await self.handler.execute_query(data[1], data[0])
            result.append(self.returned_result)
            await self.handler.helper.delete_db(data[0])

        for query in test_query:
            self.loop.run_until_complete(test(query))

        self.assertEqual(self.expected_result, result)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_execute_query_error(self, m):
        self.cursor.fetchall = mock.Mock(side_effect=Exception)
        query = ""
        self.expected_result = "(1065, 'Query was empty')"

        async def test():
            self.returned_result = await self.handler.execute_query(query, self.db_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)
