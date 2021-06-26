import asyncio
import os
import sqlite3
import unittest
import subprocess
from unittest import mock

from tanner.utils.asyncmock import AsyncMock
from tanner.utils.sqlite_db_helper import SQLITEDBHelper


class TestSQLiteDBHelper(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.filename = "/tmp/db/test_db"
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open("/tmp/db/test_db", "a").close()
        # Insert some testing data
        conn = sqlite3.connect(self.filename)
        self.cursor = conn.cursor()
        self.cursor.execute("CREATE TABLE TEST (id INTEGER PRIMARY KEY, username TEXT)")
        self.cursor.execute('INSERT INTO TEST VALUES(0, "test0")')
        conn.commit()

        self.handler = SQLITEDBHelper()
        self.returned_result = None
        self.expected_result = None

    def test_setup_db_from_config(self):
        config = {
            "name": "test_db",
            "tables": [
                {
                    "schema": "CREATE TABLE IF NOT EXISTS CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), "
                    "PASSWORD VARCHAR(15))",
                    "table_name": "CREDS",
                    "data_tokens": "I,E,P",
                }
            ],
        }

        def mock_read_config():
            return config

        self.result = []
        self.handler.read_config = mock_read_config
        self.handler.insert_dummy_data = AsyncMock()

        calls = [mock.call("CREDS", "I,E,P", mock.ANY)]

        self.expected_result = [
            [
                ("CREATE TABLE CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), PASSWORD " "VARCHAR(15))",),
                ("CREATE TABLE TEST (id INTEGER PRIMARY KEY, username TEXT)",),
            ]
        ]

        async def test():
            await self.handler.setup_db_from_config("/tmp/", self.filename)
            self.cursor.execute("SELECT sql FROM sqlite_master ORDER BY tbl_name")
            result = self.cursor.fetchall()
            self.result.append(result)
            self.handler.delete_db(self.filename)

        self.loop.run_until_complete(test())

        self.assertEqual(self.result, self.expected_result)
        self.handler.insert_dummy_data.assert_has_calls(calls, any_order=True)

    def test_get_abs_path(self):
        self.path = "db/attacker_db"
        self.returned_result = self.handler.get_abs_path(self.path, "/tmp/")
        self.expected_result = "/tmp/db/attacker_db"
        self.assertEqual(self.returned_result, self.expected_result)

    def test_get_abs_path_2(self):
        self.path = "../../tmp/db/./test_db"
        self.returned_result = self.handler.get_abs_path(self.path, "/tmp/")
        self.expected_result = "/tmp/db/test_db"
        self.assertEqual(self.returned_result, self.expected_result)

    def test_copy_db(self):
        self.attacker_db = "/tmp/db/attacker_db"

        self.returned_result = self.handler.copy_db(self.filename, self.attacker_db, "/tmp/")
        self.assertTrue(os.path.exists(self.attacker_db))

        diff_db = "diff /tmp/db/test_db /tmp/db/attacker_db"
        self.result = b""

        # Checking if new DB is same as original DB
        try:
            diff_db = subprocess.Popen(diff_db, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            self.outs, errs = diff_db.communicate(timeout=15)
            diff_db.wait()

        except subprocess.CalledProcessError:
            pass

        self.assertEqual(self.outs, self.result)

        # Deleting the DB
        os.remove("/tmp/db/attacker_db")

    def test_create_query_map(self):
        self.returned_result = self.handler.create_query_map("/tmp/db", "test_db")
        self.expected_result = {"TEST": [{"name": "id", "type": "INTEGER"}, {"name": "username", "type": "TEXT"}]}
        self.assertEqual(self.returned_result, self.expected_result)

    @mock.patch("tanner.utils.sqlite_db_helper.sqlite3")
    def test_create_query_map_error(self, sqlite):
        sqlite.OperationalError = sqlite3.OperationalError
        sqlite.connect().cursor().execute.side_effect = sqlite3.OperationalError

        with self.assertLogs(level="ERROR") as log:
            self.returned_result = self.handler.create_query_map("/tmp/db", "test_db")
            self.assertIn("Error during query map creation", log.output[0])

    def test_insert_dummy_data(self):
        def mock_generate_dummy_data(data_tokens):
            return [(1, "test1"), (2, "test2")], ["I", "L"]

        self.handler.generate_dummy_data = mock_generate_dummy_data

        self.loop.run_until_complete(self.handler.insert_dummy_data("test", "I,L", self.cursor))
        self.expected_result = [[0, "test0"], [1, "test1"], [2, "test2"]]

        result = []
        for row in self.cursor.execute("SELECT * FROM test;"):
            result.append(list(row))

        self.assertEqual(result, self.expected_result)

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)
