import unittest
import asyncio
import os
import subprocess
from unittest import mock
from tanner.config import TannerConfig
from tanner.utils.asyncmock import AsyncMock
from tanner.utils.mysql_db_helper import MySQLDBHelper


def mock_config(section, value):
    config = {"host": "127.0.0.1", "user": "root", "password": "user_pass"}

    return config[value]


class TestMySQLDBHelper(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.filename = "/tmp/db/test_db"
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open("/tmp/db/test_db", "a").close()

        self.db_name = "test_db"
        self.expected_result = None
        self.returned_result = None
        self.result = 0
        self.query_map = []
        self.handler = MySQLDBHelper()
        self.conn = None
        self.cursor = None

        with mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config) as m:

            async def connect():
                self.conn = await self.handler.connect_to_db()
                self.cursor = await self.conn.cursor()

                # Delete DB if exists
                self.returned_result = await self.handler.check_db_exists(self.db_name)
                if self.returned_result == 1:
                    await self.handler.delete_db(self.db_name)

            self.loop.run_until_complete(connect())

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_check_db_exists(self, m):
        self.expected_result = 1

        async def setup():
            await self.cursor.execute("CREATE DATABASE test_db")
            await self.conn.commit()

        async def test():
            self.returned_result = await self.handler.check_db_exists(self.db_name)

        self.loop.run_until_complete(setup())
        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_result, self.returned_result)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_check_no_db_exists(self, m):
        self.expected_result = 0

        async def test():
            self.returned_result = await self.handler.check_db_exists(self.db_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.expected_result, self.returned_result)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_setup_db_from_config(self, m):
        config = {
            "name": "test_db",
            "tables": [
                {
                    "schema": "CREATE TABLE TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)",
                    "table_name": "TEST",
                    "data_tokens": "I,L",
                },
                {
                    "schema": "CREATE TABLE CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), PASSWORD VARCHAR(15))",
                    "table_name": "CREDS",
                    "data_tokens": "I,E,P",
                },
            ],
        }

        def mock_read_config():
            return config

        self.expected_result = [
            (("ID", "int(11)", "NO", "PRI", None, ""), ("USERNAME", "text", "YES", "", None, "")),
            (
                ("ID", "int(11)", "NO", "PRI", None, ""),
                ("EMAIL", "varchar(15)", "YES", "", None, ""),
                ("PASSWORD", "varchar(15)", "YES", "", None, ""),
            ),
        ]

        self.result = []
        self.handler.read_config = mock_read_config
        self.handler.insert_dummy_data = AsyncMock()

        calls = [mock.call("TEST", "I,L", mock.ANY), mock.call("CREDS", "I,E,P", mock.ANY)]

        async def test():
            await self.handler.setup_db_from_config()

            for table in config["tables"]:
                await self.cursor.execute("USE test_db")
                await self.cursor.execute("DESCRIBE {table_name}".format(table_name=table["table_name"]))
                result = await self.cursor.fetchall()
                self.result.append(result)

        self.loop.run_until_complete(test())
        self.assertEqual(self.result, self.expected_result)
        self.handler.insert_dummy_data.assert_has_calls(calls, any_order=True)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_copy_db(self, m):
        self.expected_result = 1
        self.expected_outs = b""

        dump1 = (
            "mysqldump --compact --skip-extended-insert -h {host} -u {user} -p{password}" " test_db>/tmp/db/file1.sql"
        )
        dump1 = dump1.format(
            host=TannerConfig.get("SQLI", "host"),
            user=TannerConfig.get("SQLI", "user"),
            password=TannerConfig.get("SQLI", "password"),
        )
        dump2 = (
            "mysqldump --compact --skip-extended-insert -h {host} -u {user} -p{password}"
            " attacker_db>/tmp/db/file2.sql"
        )
        dump2 = dump2.format(
            host=TannerConfig.get("SQLI", "host"),
            user=TannerConfig.get("SQLI", "user"),
            password=TannerConfig.get("SQLI", "password"),
        )

        diff_db = "diff /tmp/db/file1.sql /tmp/db/file2.sql"

        async def setup():
            await self.cursor.execute("CREATE DATABASE test_db")

        # Checking if new DB exists
        async def test():
            self.returned_result = await self.handler.copy_db(self.db_name, "attacker_db")
            self.result = await self.handler.check_db_exists("attacker_db")

        self.loop.run_until_complete(setup())
        self.loop.run_until_complete(test())

        # Checking if new DB is exactly same as original DB
        try:
            dump_db_1 = subprocess.Popen(dump1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            dump_db_2 = subprocess.Popen(dump2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            diff_db = subprocess.Popen(diff_db, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            self.outs, errs = diff_db.communicate(timeout=15)
            dump_db_1.wait()
            dump_db_2.wait()
            diff_db.wait()

        except subprocess.CalledProcessError:
            pass

        self.assertEqual(self.result, self.expected_result)
        self.assertEqual(self.outs, self.expected_outs)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_insert_dummy_data(self, m):
        def mock_generate_dummy_data(data_tokens):
            return [(1, "test1"), (2, "test2")], ["I", "L"]

        self.handler.generate_dummy_data = mock_generate_dummy_data
        self.expected_result = ((0, "test0"), (1, "test1"), (2, "test2"))

        async def setup():
            await self.cursor.execute("CREATE DATABASE test_db")
            await self.cursor.execute("USE {db_name}".format(db_name="test_db"))
            await self.cursor.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, username TEXT)")
            await self.cursor.execute('INSERT INTO test VALUES(0, "test0")')
            await self.conn.commit()

        async def test():
            await self.handler.insert_dummy_data("test", "I,L", self.cursor)
            await self.cursor.execute("SELECT * FROM test;")
            self.returned_result = await self.cursor.fetchall()
            await self.cursor.close()
            self.conn.close()

        self.loop.run_until_complete(setup())
        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, self.expected_result)

    @mock.patch("tanner.config.TannerConfig.get", side_effect=mock_config)
    def test_create_query_map(self, m):

        self.expected_result_creds = {
            "COMMON": [{"name": "NUM", "type": "INTEGER"}],
            "CREDS": [
                {"name": "ID", "type": "INTEGER"},
                {"name": "EMAIL", "type": "TEXT"},
                {"name": "PASSWORD", "type": "TEXT"},
            ],
        }

        self.expected_result_test = {
            "COMMON": [{"name": "PARA", "type": "TEXT"}],
            "TEST": [{"name": "ID", "type": "INTEGER"}, {"name": "USERNAME", "type": "TEXT"}],
        }

        self.query = [
            ["TEST_DB", "CREATE TABLE TEST (ID INTEGER PRIMARY KEY, USERNAME TEXT)", "CREATE TABLE COMMON (PARA TEXT)"],
            [
                "CREDS_DB",
                "CREATE TABLE CREDS (ID INTEGER PRIMARY KEY, EMAIL VARCHAR(15), PASSWORD VARCHAR(15))",
                "CREATE TABLE COMMON (NUM INTEGER )",
            ],
        ]

        async def setup(data):
            await self.cursor.execute("CREATE DATABASE {db_name}".format(db_name=data[0]))
            await self.cursor.execute("USE {db_name}".format(db_name=data[0]))
            await self.cursor.execute(data[1])
            await self.cursor.execute(data[2])

        async def test(data):
            result = await self.handler.create_query_map(data[0])
            self.query_map.append(result)
            await self.handler.delete_db(data[0])

        for data in self.query:
            self.loop.run_until_complete(setup(data))
            self.loop.run_until_complete(test(data))

        self.assertEqual(self.query_map[0], self.expected_result_test)
        self.assertEqual(self.query_map[1], self.expected_result_creds)
