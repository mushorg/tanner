import asyncio
import os
import unittest
from unittest import mock

from tanner.emulators import sqli


class SqliTest(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        
        query_map = {
            'users': [{'name':'id', 'type':'INTEGER'}, {'name':'login', 'type':'text'},
                      {'name':'email', 'type':'text'}, {'name':'username', 'type':'text'},
                      {'name':'password', 'type':'text'}, {'name':'pass', 'type':'text'},
                      {'name':'log', 'type':'text'}],
            'comments': [{'name':'comment', 'type':'text'}]
        }
        self.handler = sqli.SqliEmulator('test_db', '/tmp/')
        self.handler.query_map = query_map

    def test_map_query_id(self):
        attack_value = dict(id= 'id', value= '1\'UNION SELECT 1,2,3,4')
        assert_result = 'SELECT * from users WHERE id=1 UNION SELECT 1,2,3,4;'
        result = self.handler.map_query(attack_value)
        self.assertEqual(assert_result, result)

    def test_map_query_comments(self):
        attack_value = dict(id= 'comment', value= 'some_comment" UNION SELECT 1,2 AND "1"="1')
        assert_result = 'SELECT * from comments WHERE comment="some_comment" UNION SELECT 1,2 AND "1"="1";'
        result = self.handler.map_query(attack_value)
        self.assertEqual(assert_result, result)

    def test_map_query_error(self):
        attack_value = dict(id= 'foo', value= 'bar\'UNION SELECT 1,2')
        result = self.handler.map_query(attack_value)
        self.assertIsNone(result)

    def test_get_sqli_result(self):
        attack_value = dict(id= 'id', value= '1 UNION SELECT 1,2,3,4')

        async def mock_execute_query(query, db_name):
            return [[1, 'name', 'email@mail.com', 'password'], [1, '2', '3', '4']]

        self.handler.sqli_emulator = mock.Mock()
        self.handler.sqli_emulator.execute_query = mock_execute_query

        assert_result = dict(value="[1, 'name', 'email@mail.com', 'password'] [1, '2', '3', '4']",
                             page='/index.html'
                             )
        result = self.loop.run_until_complete(self.handler.get_sqli_result(attack_value, 'foo.db'))
        self.assertEqual(assert_result, result)

    def test_get_sqli_result_error(self):
        attack_value = dict(id= 'foo', value= 'bar\'UNION SELECT 1,2')
        assert_result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near foo at line 1'
        result = self.loop.run_until_complete(self.handler.get_sqli_result(attack_value, 'foo.db'))
        self.assertEqual(assert_result, result)