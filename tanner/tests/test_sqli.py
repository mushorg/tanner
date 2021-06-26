import asyncio
import unittest
import os
from unittest import mock

from tanner.emulators import sqli


class SqliTest(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

        query_map = {
            "users": [
                {"name": "id", "type": "INTEGER"},
                {"name": "login", "type": "text"},
                {"name": "email", "type": "text"},
                {"name": "username", "type": "text"},
                {"name": "password", "type": "text"},
                {"name": "pass", "type": "text"},
                {"name": "log", "type": "text"},
            ],
            "comments": [{"name": "comment", "type": "text"}],
        }
        self.handler = sqli.SqliEmulator("test_db", "/tmp/")
        self.filename = "/tmp/db/test_db"
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open("/tmp/db/test_db", "a").close()
        self.handler.query_map = query_map
        self.sess = mock.Mock()
        self.sess.sess_uuid.hex = "d877339ec415484987b279469167af3d"

    def test_scan(self):
        attack = "1 UNION SELECT 1,2,3,4"
        assert_result = dict(name="sqli", order=2)
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_scan_negative(self):
        attack = "1 UNION 1,2,3,4"
        assert_result = None
        result = self.handler.scan(attack)
        self.assertEqual(result, assert_result)

    def test_handle(self):
        attack_params = [dict(id="id", value="1 UNION SELECT 1,2,3,4")]
        assert_result = dict(value="no such table: users", page=True)
        result = self.loop.run_until_complete(self.handler.handle(attack_params, self.sess))
        self.assertEqual(assert_result, result)

    def test_map_query_id(self):
        attack_value = dict(id="id", value="1'UNION SELECT 1,2,3,4")
        assert_result = "SELECT * from users WHERE id=1 UNION SELECT 1,2,3,4;"
        result = self.handler.map_query(attack_value)
        self.assertEqual(assert_result, result)

    def test_map_query_comments(self):
        attack_value = dict(id="comment", value='some_comment" UNION SELECT 1,2 AND "1"="1')
        assert_result = 'SELECT * from comments WHERE comment="some_comment" UNION SELECT 1,2 AND "1"="1";'
        result = self.handler.map_query(attack_value)
        self.assertEqual(assert_result, result)

    def test_map_query_error(self):
        attack_value = dict(id="foo", value="bar'UNION SELECT 1,2")
        result = self.handler.map_query(attack_value)
        self.assertIsNone(result)

    def test_get_sqli_result(self):
        attack_value = dict(id="id", value="1 UNION SELECT 1,2,3,4")

        async def mock_execute_query(query, db_name):
            return [[1, "name", "email@mail.com", "password"], [1, "2", "3", "4"]]

        self.handler.sqli_emulator = mock.Mock()
        self.handler.sqli_emulator.execute_query = mock_execute_query

        assert_result = dict(value="[1, 'name', 'email@mail.com', 'password'] [1, '2', '3', '4']", page=True)
        result = self.loop.run_until_complete(self.handler.get_sqli_result(attack_value, "foo.db"))
        self.assertEqual(assert_result, result)

    def test_get_sqli_result_error(self):
        attack_value = dict(id="foo", value="bar'UNION SELECT 1,2")
        assert_result = "SQL ERROR: near foo: syntax error"
        result = self.loop.run_until_complete(self.handler.get_sqli_result(attack_value, "foo.db"))
        self.assertEqual(assert_result, result["value"])

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)
