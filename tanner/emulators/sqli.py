import asyncio
import os
import sqlite3
import urllib.parse
import pylibinjection
from asyncio.subprocess import PIPE

from tanner.utils import sqlite_db_helper
from tanner.config import TannerConfig
from tanner.emulators import mysqli, sqlite

class SqliEmulator:
    def __init__(self, db_name, working_dir):
        if (TannerConfig.get('MYSQLI', 'enabled') == 'True'):
            self.sqli_emulator = mysqli.MySQLIEmulator(working_dir, TannerConfig.get('MYSQLI', 'db_name'))
        else:
            self.sqli_emulator = sqlite.SQLITEEmulator(db_name, working_dir)

        self.query_map = None

    @staticmethod
    def check_sqli(path):
        payload = bytes(path, 'utf-8')
        sqli = pylibinjection.detect_sqli(payload)
        return int(sqli['sqli'])

    @asyncio.coroutine
    def check_post_data(self, data):
        sqli_data = []
        for (param, value) in data['post_data'].items():
            sqli = self.check_sqli(value)
            if sqli:
                sqli_data.append((param, value))
        return sqli_data

    @asyncio.coroutine
    def check_get_data(self, path):
        request_query = urllib.parse.urlparse(path).query
        parsed_queries = urllib.parse.parse_qsl(request_query)
        for query in parsed_queries:
            sqli = self.check_sqli(query[1])
            return sqli

    @staticmethod
    def prepare_get_query(path):
        query = urllib.parse.urlparse(path).query
        parsed_query = urllib.parse.parse_qsl(query)
        return parsed_query

    @asyncio.coroutine
    def map_query(self, query):
        db_query = None
        param = query[0][0]
        param_value = query[0][1].replace('\'', ' ')
        tables = []
        for table, columns in self.query_map.items():
            for column in columns: 
                if query[0][0] == column['name']:
                    tables.append(dict(table_name=table, column=column))

        if tables:
            if tables[0]['column']['type'] == 'INTEGER':
                db_query = 'SELECT * from ' + tables[0]['table_name'] + ' WHERE ' + param + '=' + param_value + ';'
            else:
                db_query = 'SELECT * from ' + tables[0]['table_name'] + ' WHERE ' + param + '="' + param_value + '";'

        return db_query

    @asyncio.coroutine
    def get_sqli_result(self, query, attacker_db):
        db_query = yield from self.map_query(query)
        if db_query is None:
            result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near {} at line 1'.format(query[0][0])
        else:
            execute_result = yield from self.sqli_emulator.execute_query(db_query, attacker_db)
            if isinstance(execute_result, list):
                execute_result = ' '.join([str(x) for x in execute_result])
            result = dict(value=execute_result, page='/index.html')
        return result

    @asyncio.coroutine
    def handle(self, path, session, post_request=0):
        if self.query_map is None:
            self.query_map = yield from self.sqli_emulator.setup_db(self.query_map)
        if not post_request:
            path = self.prepare_get_query(path)
        attacker_db = yield from self.sqli_emulator.create_attacker_db(session)
        result = yield from self.get_sqli_result(path, attacker_db)
        return result
