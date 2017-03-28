import asyncio
import elizabeth
import json
import logging
import os
import random
import re
import shutil
import sqlite3

from tanner.config import TannerConfig


class DBHelper:
    def __init__(self):
        self.logger = logging.getLogger('tanner.db_helper.DBHelper')

    @asyncio.coroutine
    def read_config(self, working_dir):
        with open(TannerConfig.get('DATA', 'db_config')) as db_config:
            try:
                config = json.load(db_config)
            except json.JSONDecodeError as json_error:
                self.logger.info('Failed to load json: %s', json_error)
            else:
                return config

    @staticmethod
    @asyncio.coroutine
    def insert_dummy_data(table_name, data_tokens, cursor):
        """
        Insert dummy data based on data tokens
        I - integer id
        L - login/username
        E - email
        P - password
        T - piece of text
        :return:
        """

        token_list = data_tokens.split(',')

        samples_count = random.randint(100, 1000)
        inserted_data = []
        for i in range(samples_count):
            values = []
            for token in token_list:
                if token == 'I':
                    values.append(i)
                if token == 'L':
                    data = elizabeth.Personal().username()
                    values.append(data)
                if token == 'E':
                    data = elizabeth.Personal().email()
                    values.append(data)
                if token == 'P':
                    data = elizabeth.Personal().password()
                    values.append(data)
                if token == 'T':
                    sample_length = random.randint(1,10)
                    data = elizabeth.Text().text(quantity= sample_length)
                    values.append(data)
            inserted_data.append(tuple(values))

        inserted_string_patt = '?'
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        cursor.executemany("INSERT INTO " + table_name + " VALUES(" +
                           inserted_string_patt + ")", inserted_data)

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
