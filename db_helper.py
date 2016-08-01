import sqlite3
import json
import random
import shutil
import os
import re


class DBHelper:
    @staticmethod
    def read_config():
        if not os.path.exists('/opt/tanner/db/db_config.json'):
            shutil.move('data/db_config.json', '/opt/tanner/db/db_config.json')
        with open('/opt/tanner/db/db_config.json') as db_config:
            try:
                config = json.load(db_config)
            except json.JSONDecodeError as e:
                print('Failed to load json', e)
            else:
                return config

    @staticmethod
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

        with open('/usr/share/dict/words') as dummy:
            dummy_data = dummy.read()
            dummy_data = dummy_data.split('\n')
            dummy_data = [x for x in dummy_data if (len(x) > 5 and re.match(re.compile('[0-9a-zA-Z]'), x))]

        domains = ['.com', '.net', '.org']
        token_list = data_tokens.split(',')

        samples_count = random.randint(100, 1000)
        inserted_data = []
        for i in range(samples_count):
            values = []
            for token in token_list:
                if token == 'I':
                    values.append(i)
                if token == 'L':
                    data = random.choice(dummy_data)
                    values.append(data)
                if token == 'E':
                    data = random.choice(dummy_data) + "@" + str.lower(random.choice(dummy_data)) + random.choice(domains)
                    values.append(data)
                if token == 'P':
                    data = random.choice(dummy_data)
                    values.append(data)
                if token == 'T':
                    data = 'This is a comment number' + str(i)
                    values.append(data)
            inserted_data.append(tuple(values))

        inserted_string_patt = '?'
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        cursor.executemany("INSERT INTO " + table_name + " VALUES(" + inserted_string_patt + ")", inserted_data)

    def setup_db_from_config(self, working_dir, name=None):
        config = self.read_config()
        if name is not None:
            db_name = working_dir + name
        else:
            db_name = working_dir + config['name'] + '.db'

        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        for table in config['tables']:
            query = table['schema']
            c.execute(query)
            self.insert_dummy_data(table['table_name'], table['data_tokens'], c)
            conn.commit()

        conn.close()

    @staticmethod
    def get_abs_path(path, working_dir):
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(working_dir, path))
        return path

    def copy_db(self, src, dst, working_dir):
        src = self.get_abs_path(src, working_dir)
        dst = self.get_abs_path(dst, working_dir)
        if os.path.exists(dst):
            print("Destination already exists")
            return
        shutil.copy(src, dst)
        return dst
