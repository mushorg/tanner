import asyncio
import json
import logging
import os
import random
import shutil
import sqlite3

from tanner.config import TannerConfig
from tanner.utils.base_db_helper import BaseDBHelper

class SQLITEDBHelper(BaseDBHelper):
    def __init__(self):
        super(SQLITEDBHelper, self).__init__()
        self.logger = logging.getLogger('tanner.sqlite_db_helper.SQLITEDBHelper')
        self.inserted_string_pattern = '?'

    @asyncio.coroutine
    def setup_db_from_config(self, working_dir, name=None):
        config = yield from self.read_config(working_dir)
        if name is not None:
            db_name = os.path.join(working_dir, name)
        else:
            db_name = os.path.join(working_dir, config['name'] + '.db')

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        for table in config['tables']:
            query = table['schema']
            cursor.execute(query)
            yield from self.insert_dummy_data(table['table_name'], table['data_tokens'], cursor)
            conn.commit()

        conn.close()

    @staticmethod
    def get_abs_path(path, working_dir):
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(working_dir, path))
        return path

    @asyncio.coroutine
    def copy_db(self, src, dst, working_dir):
        src = self.get_abs_path(src, working_dir)
        dst = self.get_abs_path(dst, working_dir)
        if os.path.exists(dst):
            self.logger.info('Attacker db already exists')
        else:
            shutil.copy(src, dst)
        return dst

    @asyncio.coroutine
    def create_query_map(self, working_dir, db_name, ):
        query_map = {}
        tables = []

        db = os.path.join(working_dir, db_name)
        conn = sqlite3.connect(db)
        cursor = conn.cursor()

        select_tables = 'SELECT name FROM sqlite_master WHERE type=\'table\''

        try:
            for row in cursor.execute(select_tables):
                tables.append(row[0])
        except sqlite3.OperationalError as sqlite_error:
            self.logger.error('Error during query map creation: %s', sqlite_error)
        else:
            query_map = dict.fromkeys(tables)
            for table in tables:
                query = 'PRAGMA table_info(' + table + ')'
                columns = []
                try:
                    for row in cursor.execute(query):
                        columns.append(dict(name=row[1], type=row[2]))
                    query_map[table] = columns
                except sqlite3.OperationalError as sqlite_error:
                    self.logger.error('Error during query map creation: %s', sqlite_error)
        return query_map
