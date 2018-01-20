import asyncio
import os
import sqlite3
import unittest
from unittest import mock

from tanner.emulators import sqlite


class SqliteTest(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        self.filename = '/tmp/db/test_db'
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        open('/tmp/db/test_db', 'a').close()
        # Insert some testing data
        conn = sqlite3.connect(self.filename)
        self.cursor = conn.cursor()
        self.cursor.execute('CREATE TABLE test (id INTEGER PRIMARY KEY, username TEXT);')
        self.cursor.execute('INSERT INTO TEST VALUES(0, "test0")')
        conn.commit()

        self.handler = sqlite.SQLITEEmulator('test_db', '/tmp/')

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)

    def test_db_copy(self):
        session = mock.Mock()
        session.sess_uuid.hex = 'd877339ec415484987b279469167af3d'
        self.loop.run_until_complete(self.handler.create_attacker_db(session))
        self.assertTrue(os.path.exists('/tmp/db/attacker_d877339ec415484987b279469167af3d'))

    def test_create_query_map(self):
        result = self.handler.helper.create_query_map('/tmp/db', 'test_db')
        assert_result = {'test': [{'name': 'id', 'type': 'INTEGER'}, {'name': 'username', 'type': 'text'}]}
        self.assertEqual(result, assert_result)

    def test_insert_dummy_data(self):
        def mock_generate_dummy_data(data_tokens):
            return [(1, 'test1'), (2, 'test2')], ['I', 'L']

        self.handler.helper.generate_dummy_data = mock_generate_dummy_data

        self.loop.run_until_complete(self.handler.helper.insert_dummy_data('test', 'I,L', self.cursor))
        assert_result = [[0, 'test0'], [1, 'test1'], [2, 'test2']]

        result = []
        for row in self.cursor.execute('SELECT * FROM test;'):
            result.append(list(row))

        self.assertEqual(result, assert_result)
