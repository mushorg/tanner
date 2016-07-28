import asyncio
import sqlite3
import os
import db_helper
import urllib.parse


class SqliEmulator:
    def __init__(self, db_name, working_dir):
        self.db_name = db_name
        self.working_dir = working_dir
        self.helper = db_helper.DBHelper()
        self.setup_db()

    def setup_db(self):
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)
        db = os.path.join(self.working_dir, self.db_name)
        if not os.path.exists(db):
            self.helper.setup_db_from_config(self.working_dir, self.db_name)

    def map_query(self, query):
        db_query = None
        queries = [
            {
                'param': ['id'],
                'query': 'SELECT * from users WHERE id=%s'
            },
            {
                'param': ['email'],
                'query': 'SELECT * from users WHERE email=%s'
            },
            {
                'param': ['comment'],
                'query': 'SELECT * from comments WHERE comment=%s'
            },
            {
                'param': ['login', 'username', 'log'],
                'query': 'SELECT * from users WHERE username=%s'
            },

        ]

        parsed_query = urllib.parse.parse_qsl(query)

        for q in queries:
            for p in q['param']:
                if p == parsed_query[0][0]:
                    parsed_query = parsed_query[0][1]
                    parsed_query = parsed_query.replace('\'', ' ')
                    db_query = q['query']

        if db_query is None:
            db_query = 'You have an error in your SQL syntax; check the manual\
                        that corresponds to your MySQL server version for the\
                        right syntax to use near {} at line 1'.format(parsed_query[0][0])
        return db_query, parsed_query

    def execute_query(self, query, param, db):
        result = []
        conn = sqlite3.connect(self.working_dir + db)
        c = conn.cursor()
        print(query)
        try:
            c.execute(query % param)
            for row in c:
                result.append(list(row))
        except sqlite3.OperationalError as e:
            result = str(e)
        return result

    @asyncio.coroutine
    def get_sqli_result(self, path, dummy_db):
        path = urllib.parse.unquote(path)
        query = urllib.parse.urlparse(path).query
        db_query, val = self.map_query(query)
        result = self.execute_query(db_query, val, dummy_db)
        return result

    @asyncio.coroutine
    def handle(self, path, session):
        dummy_db = session.uuid.hex + '.db'
        self.helper.copy_db(self.db_name, dummy_db, self.working_dir)
        result = yield from self.get_sqli_result(path, dummy_db)
        return result
