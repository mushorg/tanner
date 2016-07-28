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
                'query': 'SELECT * from users WHERE id='
            },
            {
                'param': ['email'],
                'query': 'SELECT * from users WHERE email='
            },
            {
                'param': ['comment'],
                'query': 'SELECT * from comments WHERE comment='
            },
            {
                'param': ['login', 'username', 'log'],
                'query': 'SELECT * from users WHERE username='
            },

        ]

        for q in queries:
            for p in q['param']:
                if p in query:
                    s = urllib.parse.parse_qsl(query)[0][1]
                    s = s.replace('\'', ' ')
                    db_query = q['query'] + s + ';'

        return db_query

    def execute_query(self, query, db):
        result = []
        conn = sqlite3.connect(self.working_dir + db)
        c = conn.cursor()
        print(query)
        try:
            c.execute(query)
            for row in c:
                result.append(list(row))
        except sqlite3.OperationalError as e:
            result = str(e)
        return result

    @asyncio.coroutine
    def get_sqli_result(self, path, dummy_db):
        path = urllib.parse.unquote(path)
        query = urllib.parse.urlparse(path).query
        db_query = self.map_query(query)
        result = self.execute_query(db_query, dummy_db)
        return result

    @asyncio.coroutine
    def handle(self, path, session):
        dummy_db = session.uuid.hex + '.db'
        self.helper.copy_db(self.db_name, dummy_db, self.working_dir)
        result = yield from self.get_sqli_result(path, dummy_db)
        return result
