import unittest
import asyncio
import os
from unittest import mock
import sqli_emulator

class SqliTest(unittest.TestCase):

    def setUp(self):
        self.handler = sqli_emulator.SqliEmulator('test.db','/tmp/')

    def test_db_copy(self):
        session = mock.Mock()
        session.uuid.hex = 'ad16014d-9b4a-451d-a6d1-fc8681566458'
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.handler.create_attacker_db(session))
        self.assertTrue(os.path.exists('/tmp/ad16014d-9b4a-451d-a6d1-fc8681566458.db'))

    def test_map_query_id(self):
        query = 'id=1\'UNION SELECT 1,2,3,4'
        assert_result = 'SELECT * from users WHERE id=1 UNION SELECT 1,2,3,4;'
        result = self.handler.map_query(query)
        self.assertEqual(assert_result,result)

    def test_map_query_comments(self):
        query = 'comment=some_comment\'UNION SELECT 1,2'
        assert_result = 'SELECT * from comments WHERE comment=some_comment UNION SELECT 1,2;'
        result = self.handler.map_query(query)
        self.assertEqual(assert_result, result)

    def test_map_query_error(self):
        query = 'foo=bar\'UNION SELECT 1,2'
        assert_result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near foo at line 1'
        result = self.handler.map_query(query)
        self.assertEqual(assert_result, result)