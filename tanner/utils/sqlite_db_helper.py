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

    async def setup_db_from_config(self, working_dir, name=None):
        config = self.read_config()
        if name is not None:
            db_name = os.path.join(working_dir, name)
        else:
            db_name = os.path.join(working_dir, config['name'])

        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        for table in config['tables']:
            query = table['schema']
            cursor.execute(query)
            await self.insert_dummy_data(table['table_name'], table['data_tokens'], cursor)
            conn.commit()

        conn.close()

    @staticmethod
    def get_abs_path(path, working_dir):
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(working_dir, path))
        return path

    @staticmethod
    def delete_db(db):
        if db is not None and os.path.exists(db):
            os.remove(db)

    def copy_db(self, src, dst, working_dir):
        src = self.get_abs_path(src, working_dir)
        dst = self.get_abs_path(dst, working_dir)
        if os.path.exists(dst):
            self.logger.info('Attacker db already exists')
        else:
            shutil.copy(src, dst)
        return dst

    async def insert_dummy_data(self, table_name, data_tokens, cursor):
        inserted_data, token_list = self.generate_dummy_data(data_tokens)

        inserted_string_patt = '?'
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        cursor.executemany("INSERT INTO " + table_name + " VALUES(" +
                           inserted_string_patt + ")", inserted_data)

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
