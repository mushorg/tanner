import asyncio
import os
import sqlite3
import urllib.parse
import pylibinjection
from asyncio.subprocess import PIPE

from tanner.utils import db_helper
from tanner import config


class SqliEmulator:
    def __init__(self, db_name, working_dir):
        self.db_name = db_name
        self.working_dir = os.path.join(working_dir, 'db/')
        self.helper = db_helper.DBHelper()
        self.query_map = None

    @asyncio.coroutine
    def setup_db(self):
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)
        db = os.path.join(self.working_dir, self.db_name)
        if not os.path.exists(db):
            yield from self.helper.setup_db_from_config(self.working_dir, self.db_name)
        if self.query_map is None:
            self.query_map = yield from self.helper.create_query_map(self.working_dir, self.db_name)

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

    @asyncio.coroutine
    def create_attacker_db(self, session):
        attacker_db_name = session.sess_uuid.hex + '.db'
        attacker_db = yield from self.helper.copy_db(self.db_name,
                                                     attacker_db_name,
                                                     self.working_dir
                                                     )
        session.associate_db(attacker_db)
        return attacker_db

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
        tables = [k for k, v in self.query_map.items() if query[0][0] in v]
        if tables:
            db_query = 'SELECT * from ' + tables[0] + ' WHERE ' + param + '=' + param_value + ';'

        return db_query

    @staticmethod
    def execute_query(query, db):
        result = []
        conn = sqlite3.connect(db)
        cursor = conn.cursor()
        try:
            for row in cursor.execute(query):
                result.append(list(row))
        except sqlite3.OperationalError as sqlite_error:
            result = str(sqlite_error)
        return result

    @asyncio.coroutine
    def get_sqli_result(self, query, attacker_db):
        db_query = yield from self.map_query(query)
        if db_query is None:
            result = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near {} at line 1'.format(query[0][0])
        else:
            execute_result = self.execute_query(db_query, attacker_db)
            if isinstance(execute_result, list):
                execute_result = ' '.join([str(x) for x in execute_result])
            result = dict(value=execute_result, page='/index.html')
        return result

    @asyncio.coroutine
    def handle(self, path, session, post_request=0):
        yield from self.setup_db()
        if not post_request:
            path = self.prepare_get_query(path)
        attacker_db = yield from self.create_attacker_db(session)
        result = yield from self.get_sqli_result(path, attacker_db)
        return result
