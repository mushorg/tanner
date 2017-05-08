import asyncio
import json
import logging
import subprocess
import aiomysql

from tanner.config import TannerConfig
from tanner.utils.base_db_helper import BaseDBHelper

class MySQLDBHelper(BaseDBHelper):
    def __init__(self):
        super(MySQLDBHelper, self).__init__()
        self.logger = logging.getLogger('tanner.db_helper.MySQLDBHelper')

    @asyncio.coroutine
    def connect_to_db(self):
        conn = yield from aiomysql.connect(host = TannerConfig.get('MYSQLI', 'host'),
                                           user = TannerConfig.get('MYSQLI', 'user'),
                                           password = TannerConfig.get('MYSQLI', 'password')
                                           )
        return conn

    @asyncio.coroutine
    def check_db_exists(self, db_name, ):
        conn = yield from self.connect_to_db()
        cursor = yield from conn.cursor()
        check_DB_exists_query = 'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA '
        check_DB_exists_query+= 'WHERE SCHEMA_NAME=\'{db_name}\''.format(db_name=db_name)
        yield from cursor.execute(check_DB_exists_query)
        result = yield from cursor.fetchall()
        #return 0 if no such database exists else 1
        return len(result)
        
    @asyncio.coroutine
    def setup_db_from_config(self, name=None):
        config = yield from self.read_config()
        if name is not None:
            db_name = name
        else:
            db_name = config['name']
               
        conn = yield from self.connect_to_db()
        cursor = yield from conn.cursor()
        create_db_query = 'CREATE DATABASE {db_name}'
        yield from cursor.execute(create_db_query.format(db_name=db_name))
        yield from cursor.execute('USE {db_name}'.format(db_name=db_name))

        for table in config['tables']:
            query = table['schema']
            yield from cursor.execute(query)
            yield from self.insert_dummy_data(table['table_name'], table['data_tokens'], cursor)
            yield from conn.commit()

        conn.close()

    @asyncio.coroutine
    def copy_db(self, user_db, attacker_db):
        db_exists = yield from self.check_db_exists(attacker_db)
        if db_exists:
            self.logger.info('Attacker db already exists')
        else:
            #create new attacker db
            conn = yield from self.connect_to_db()
            cursor = yield from conn.cursor()
            yield from cursor.execute('CREATE DATABASE {db_name}'.format(db_name=attacker_db))
            conn.close()
            # copy user db to attacker db
            dump_db_cmd = 'mysqldump -h {host} -u {user} -p{password} {db_name}'
            restore_db_cmd = 'mysql -h {host} -u {user} -p{password} {db_name}'
            dump_db_cmd = dump_db_cmd.format(host = TannerConfig.get('MYSQLI', 'host'),
                                             user = TannerConfig.get('MYSQLI', 'user'),
                                             password = TannerConfig.get('MYSQLI', 'password'),
                                             db_name=user_db
                                             )
            restore_db_cmd = restore_db_cmd.format(host = TannerConfig.get('MYSQLI', 'host'),
                                                user = TannerConfig.get('MYSQLI', 'user'),
                                                password = TannerConfig.get('MYSQLI', 'password'),
                                                db_name=attacker_db
                                                )
            try:
                dump_db_process = subprocess.Popen(dump_db_cmd, stdout = subprocess.PIPE, shell = True)
                restore_db_process = subprocess.Popen(restore_db_cmd, stdin = dump_db_process.stdout, shell = True)
                dump_db_process.stdout.close()
                dump_db_process.wait()
                restore_db_process.wait()
            except subprocess.CalledProcessError as e:
                self.logger.error('Error during copying sql database : %s' % e)
        return attacker_db

    @asyncio.coroutine
    def insert_dummy_data(self, table_name, data_tokens, cursor):
        inserted_data, token_list = yield from self.generate_dummy_data(data_tokens)

        inserted_string_patt = '%s'
        if len(token_list) > 1:
            inserted_string_patt += ','
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        yield from cursor.executemany("INSERT INTO " + table_name + " VALUES(" +
                                      inserted_string_patt + ")", inserted_data)

    @asyncio.coroutine
    def create_query_map(self, db_name):
        query_map = {}
        tables = []
        conn = yield from self.connect_to_db()
        cursor = yield from conn.cursor()

        select_tables = 'SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema= \'{db_name}\''

        try:
            yield from cursor.execute(select_tables.format(db_name=db_name))
            result = yield from cursor.fetchall()
            for row in result:
                tables.append(row[0])
        except Exception as e:
            self.logger.error('Error during query map creation')
        else:
            query_map = dict.fromkeys(tables)
            for table in tables:
                query = 'SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name= \'{table_name}\' AND table_schema= \'{db_name}\''
                columns = []
                try:
                    yield from cursor.execute(query.format(table_name=table, db_name=db_name))
                    result = yield from cursor.fetchall()
                    for row in result:
                        if (row[7] == 'int'):
                            columns.append(dict(name=row[3], type='INTEGER'))
                        else:
                            columns.append(dict(name=row[3], type='TEXT'))
                    query_map[table] = columns
                except :
                    self.logger.error('Error during query map creation')
        return query_map
