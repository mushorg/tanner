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

    def execute_query(self, query, table):
        pass

    @asyncio.coroutine
    def get_sqli_result(self, path, dummy_db):
        query = urllib.parse.urlparse(path).query

    @asyncio.coroutine
    def handle(self, path, session):
        dummy_db = session.uuid.hex + '.db'
        self.helper.copy_db(self.db_name, dummy_db, self.working_dir)
        result = yield from self.get_sqli_result(path, dummy_db)