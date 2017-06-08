import os
import pylibinjection
import sqlite3
import urllib.parse

from tanner.utils import sqlite_db_helper
from tanner.config import TannerConfig
from tanner.emulators import mysqli, sqlite

class SqliEmulator:
    def __init__(self, db_name, working_dir):
        if (TannerConfig.get('SQLI', 'type') == 'MySQL'):
            self.sqli_emulator = mysqli.MySQLIEmulator(db_name)
        else:
            self.sqli_emulator = sqlite.SQLITEEmulator(db_name, working_dir)

        self.query_map = None

    @staticmethod
    def check_sqli(path):
        payload = bytes(path, 'utf-8')
        sqli = pylibinjection.detect_sqli(payload)
        return int(sqli['sqli'])

    def check_post_data(self, data):
        sqli_data = []
        for (param, value) in data['post_data'].items():
            sqli = self.check_sqli(value)
            if sqli:
                sqli_data.append((param, value))
        return sqli_data

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

    async def get_sqli_result(self, query, attacker_db):
        db_query = self.map_query(query)
        if db_query is None:
            result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near {} at line 1'.format(query[0][0])
        else:
            execute_result = await self.sqli_emulator.execute_query(db_query, attacker_db)
            if isinstance(execute_result, list):
                execute_result = ' '.join([str(x) for x in execute_result])
            result = dict(value=execute_result, page='/index.html')
        return result

    async def handle(self, path, session, post_request=0):
        if self.query_map is None:
            self.query_map = await self.sqli_emulator.setup_db(self.query_map)
        if not post_request:
            path = self.prepare_get_query(path)
        attacker_db = await self.sqli_emulator.create_attacker_db(session)
        result = await self.get_sqli_result(path, attacker_db)
        return result
