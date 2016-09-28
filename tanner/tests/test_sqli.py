import asyncio
import os
import unittest
from unittest import mock

from tanner.emulators import sqli


class SqliTest(unittest.TestCase):
    def setUp(self):
        filename = '/tmp/db/test.db'
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        open('/tmp/db/test.db', 'a').close()

        query_map = {
            'users': ['id', 'login', 'email', 'username', 'password', 'pass', 'log'],
            'comments': ['comment']
        }
        self.handler = sqli.SqliEmulator('test.db', '/tmp/')
        self.handler.query_map = query_map

    def test_db_copy(self):
        session = mock.Mock()
        session.uuid.hex = 'ad16014d-9b4a-451d-a6d1-fc8681566458'
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.handler.create_attacker_db(session))
        self.assertTrue(os.path.exists('/tmp/db/ad16014d-9b4a-451d-a6d1-fc8681566458.db'))

    def test_map_query_id(self):
        query = [('id', '1\'UNION SELECT 1,2,3,4')]
        assert_result = 'SELECT * from users WHERE id=1 UNION SELECT 1,2,3,4;'
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(self.handler.map_query(query))
        self.assertEqual(assert_result, result)

    def test_map_query_comments(self):
        query = [('comment', 'some_comment\'UNION SELECT 1,2')]
        assert_result = 'SELECT * from comments WHERE comment=some_comment UNION SELECT 1,2;'
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(self.handler.map_query(query))
        self.assertEqual(assert_result, result)

    def test_map_query_error(self):
        query = [('foo', 'bar\'UNION SELECT 1,2')]
        assert_result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near foo at line 1'
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(self.handler.get_sqli_result(query, 'foo.db'))
        self.assertEqual(assert_result, result)
