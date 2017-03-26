import asyncio
import elizabeth
import json
import logging
import os
import random
import re
import shutil
import pymysql

from tanner.config import TannerConfig


class MySQLDBHelper:
    def __init__(self):
        self.logger = logging.getLogger('tanner.db_helper.mysqlDBHelper')

    @asyncio.coroutine
    def read_config(self):
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

        inserted_string_patt = '%s'
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        cursor.executemany("INSERT INTO " + table_name + " VALUES(" +
                           inserted_string_patt + ")", inserted_data)

    @asyncio.coroutine
    def setup_db_from_config(self, conn, name=None):
        config = yield from self.read_config()
        if name is not None:
            db_name = name
        else:
            db_name = config['name']
               
        cursor = conn.cursor()
        create_db_query = 'CREATE DATABASE {db_name}'
        cursor.execute(create_db_query.format(db_name=db_name))
        cursor.execute('USE {db_name}'.format(db_name=db_name))

        for table in config['tables']:
            query = table['schema']
            cursor.execute(query)
            yield from self.insert_dummy_data(table['table_name'], table['data_tokens'], cursor)
            conn.commit()


    @asyncio.coroutine
    def create_query_map(self, conn, db_name, ):
        query_map = {}
        tables = []

        cursor = conn.cursor()

        select_tables = 'SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema= \'{db_name}\''

        try:
            cursor.execute(select_tables.format(db_name=db_name))
            for row in cursor.fetchall():
                tables.append(row[0])
        except Exception as e:
            self.logger.error('Error during query map creation')
        else:
            query_map = dict.fromkeys(tables)
            for table in tables:
                query = 'SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema= \'{db_name}\''
                columns = []
                try:
                    cursor.execute(query.format(db_name=db_name))
                    for row in cursor.fetchall():
                        columns.append(row[0])
                    query_map[table] = columns
                except :
                    self.logger.error('Error during query map creation')
        return query_map
