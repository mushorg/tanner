import asyncio
import os
import sqlite3
import unittest
from unittest import mock

from tanner.utils.asyncmock import AsyncMock
from tanner.emulators import sqlite


class SqliteTest(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.filename = "/tmp/db/test_db"
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open("/tmp/db/test_db", "a").close()
        # Insert some testing data
        self.conn = sqlite3.connect(self.filename)
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, username TEXT)")
        self.cursor.execute('INSERT INTO TEST VALUES(0, "test0")')
        self.conn.commit()

        self.handler = sqlite.SQLITEEmulator("test_db", "/tmp/")
        self.returned_result = None
        self.expected_result = None

    def test_setup_db(self):

        self.handler.helper.create_query_map = mock.Mock(
            return_value={"test": [{"name": "id", "type": "INTEGER"}, {"name": "username", "type": "TEXT"}]}
        )
        self.handler.helper.setup_db_from_config = mock.Mock()

        async def test():
            self.returned_result = await self.handler.setup_db()

        self.loop.run_until_complete(test())
        self.handler.helper.create_query_map.assert_called_with("/tmp/db/", "test_db")
        assert not self.handler.helper.setup_db_from_config.called

    def test_setup_db_not_exists(self):

        self.handler.helper.create_query_map = mock.Mock(
            return_value={"test": [{"name": "id", "type": "INTEGER"}, {"name": "username", "type": "TEXT"}]}
        )
        self.handler.helper.setup_db_from_config = AsyncMock()

        async def test():
            os.remove(self.filename)
            self.returned_result = await self.handler.setup_db()

        self.loop.run_until_complete(test())
        self.handler.helper.setup_db_from_config.assert_called_with("/tmp/db/", "test_db")
        self.handler.helper.create_query_map.assert_called_with("/tmp/db/", "test_db")

    def test_create_attacker_db(self):
        session = mock.Mock()
        session.sess_uuid.hex = "d877339ec415484987b279469167af3d"
        self.loop.run_until_complete(self.handler.create_attacker_db(session))
        self.assertTrue(os.path.exists("/tmp/db/attacker_d877339ec415484987b279469167af3d"))

    def test_execute_query(self):

        self.expected_result = [[[1, "test_name"]], [[1, "test@domain.com", "test_pass"]]]

        result = []
        self.query = [
            [
                "/tmp/db/TEST_DB",
                "CREATE TABLE IF NOT EXISTS TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)",
                'INSERT INTO TEST VALUES(1, "test_name")',
            ],
            [
                "/tmp/db/CREDS_DB",
                "CREATE TABLE IF NOT EXISTS CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), " "PASSWORD VARCHAR(15))",
                "INSERT INTO CREDS VALUES(1, 'test@domain.com', 'test_pass')",
            ],
        ]
        test_query = [["/tmp/db/TEST_DB", "SELECT * FROM TEST"], ["/tmp/db/CREDS_DB", "SELECT * FROM CREDS"]]

        def setup(data):
            os.makedirs(os.path.dirname(data[0]), exist_ok=True)
            self.conn = sqlite3.connect(data[0])
            self.cursor = self.conn.cursor()
            self.cursor.execute(data[1])
            self.cursor.execute(data[2])
            self.conn.commit()

        for data in self.query:
            setup(data)

        async def test(data):
            self.returned_result = await self.handler.execute_query(data[1], data[0])
            result.append(self.returned_result)
            self.handler.helper.delete_db(data[0])

        for query in test_query:
            self.loop.run_until_complete(test(query))

        self.assertEqual(self.expected_result, result)

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)
