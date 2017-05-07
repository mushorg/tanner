import asyncio
import elizabeth
import json
import logging
import random

from tanner.config import TannerConfig


class BaseDBHelper:
    def __init__(self):
        self.logger = logging.getLogger('tanner.base_db_helper.BaseDBHelper')

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

        inserted_string_patt = self.inserted_string_pattern
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        cursor.executemany("INSERT INTO " + table_name + " VALUES(" +
                           inserted_string_patt + ")", inserted_data)
