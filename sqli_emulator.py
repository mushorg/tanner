import asyncio
import sqlite3
import os
import urllib.parse
import db_helper


class SqliEmulator:
    def __init__(self, db_name, working_dir):
        self.db_name = db_name
        self.working_dir = working_dir
        self.helper = db_helper.DBHelper()

    @asyncio.coroutine
    def setup_db(self):
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)
        db = os.path.join(self.working_dir, self.db_name)
        if not os.path.exists(db):
            yield from self.helper.setup_db_from_config(self.working_dir, self.db_name)

    @asyncio.coroutine
    def create_query_map(self):
        query_map = {}
        tables = []

        db = os.path.join(self.working_dir, self.db_name)
        conn = sqlite3.connect(db)
        c = conn.cursor()

        select_tables = 'SELECT name FROM sqlite_master WHERE type=\'table\''

        try:
            for row in c.execute(select_tables):
                tables.append(row[0])
        except sqlite3.OperationalError as e:
            print(e)
        else:
            query_map = dict.fromkeys(tables)
            for table in tables:
                query = 'PRAGMA table_info(' + table + ')'
                columns = []
                try:
                    for row in c.execute(query):
                        columns.append(row[1])
                    query_map[table] = columns
                except sqlite3.OperationalError as e:
                    print(e)
        return query_map

    @asyncio.coroutine
    def map_query(self, query):
        db_query = None
        query_map = yield from self.create_query_map()
        parsed_query = urllib.parse.parse_qsl(query)
        param = parsed_query[0][0]
        param_value = parsed_query[0][1].replace('\'', ' ')
        tables = [k for k, v in query_map.items() if parsed_query[0][0] in v]
        if tables:
            db_query = 'SELECT * from ' + tables[0] + ' WHERE ' + param + '=' + param_value + ';'

        if db_query is None:
            db_query = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near {} at line 1'.format(param)
        return db_query

    @staticmethod
    def execute_query(query, db):
        result = []
        conn = sqlite3.connect(db)
        c = conn.cursor()
        print(query)
        try:
            for row in c.execute(query):
                result.append(list(row))
        except sqlite3.OperationalError as e:
            result = str(e)
        return result

    @asyncio.coroutine
    def get_sqli_result(self, path, dummy_db):
        path = urllib.parse.unquote(path)
        query = urllib.parse.urlparse(path).query
        db_query = yield from self.map_query(query)
        execute_result = self.execute_query(db_query, dummy_db)
        if type(execute_result) == list:
            execute_result = ' '.join([str(x) for x in execute_result])
        result = dict(value=execute_result, page='/index.html')
        return result

    @asyncio.coroutine
    def create_attacker_db(self, session):
        attacker_db_name = session.uuid.hex + '.db'
        attacker_db = yield from self.helper.copy_db(self.db_name, attacker_db_name, self.working_dir)
        session.associate_db(attacker_db)
        return attacker_db

    @asyncio.coroutine
    def handle(self, path, session):
        yield from self.setup_db()
        attacker_db = yield from self.create_attacker_db(session)
        result = yield from self.get_sqli_result(path, attacker_db)
        return result
