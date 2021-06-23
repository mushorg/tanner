import logging
import subprocess
import aiomysql

from tanner.config import TannerConfig
from tanner.utils.base_db_helper import BaseDBHelper


class MySQLDBHelper(BaseDBHelper):

    # Helper Utility of basic functions for mysqli emulator

    def __init__(self):
        super(MySQLDBHelper, self).__init__()
        self.logger = logging.getLogger("tanner.db_helper.MySQLDBHelper")

    async def connect_to_db(self):
        """
        Creates a aiomysql connection
        :return: connection object
        """

        conn = await aiomysql.connect(
            host=TannerConfig.get("SQLI", "host"),
            user=TannerConfig.get("SQLI", "user"),
            password=TannerConfig.get("SQLI", "password"),
        )
        return conn

    async def check_db_exists(self, db_name):
        """
        Checks if DB exists or not
        :param db_name (str): mysql db name
        :return: result (int): 0 if no such database exists else 1
        """

        conn = await self.connect_to_db()
        cursor = await conn.cursor()
        check_DB_exists_query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA "
        check_DB_exists_query += "WHERE SCHEMA_NAME='{db_name}'".format(db_name=db_name)
        await cursor.execute(check_DB_exists_query)
        result = await cursor.fetchall()
        return len(result)

    async def setup_db_from_config(self, name=None):
        """
        Helper function to setup DB from db_config.json and inserts dummy data in the created DB.
        :param name (str): database name
        """

        config = self.read_config()
        if name is not None:
            db_name = name
        else:
            db_name = config["name"]

        conn = await self.connect_to_db()
        cursor = await conn.cursor()
        create_db_query = "CREATE DATABASE {db_name}"
        await cursor.execute(create_db_query.format(db_name=db_name))
        await cursor.execute("USE {db_name}".format(db_name=db_name))

        for table in config["tables"]:
            query = table["schema"]
            await cursor.execute(query)
            await self.insert_dummy_data(table["table_name"], table["data_tokens"], cursor)
            await conn.commit()

        conn.close()

    async def delete_db(self, db):
        """
        Deletes the database
        :param db (str): db name to be deleted
        """

        conn = await self.connect_to_db()
        cursor = await conn.cursor()
        delete_db_query = "DROP DATABASE {db_name}"
        await cursor.execute(delete_db_query.format(db_name=db))
        await conn.commit()
        conn.close()

    async def copy_db(self, user_db, attacker_db):
        """
        Copies the user database to new attacker database
        :param user_db (str): existing user db
        :param attacker_db (str): new db to be created
        :return: new created db (str)
        """

        db_exists = await self.check_db_exists(attacker_db)
        if db_exists:
            self.logger.info("Attacker db already exists")
        else:
            # create new attacker db
            conn = await self.connect_to_db()
            cursor = await conn.cursor()
            await cursor.execute("CREATE DATABASE {db_name}".format(db_name=attacker_db))
            conn.close()
            # copy user db to attacker db
            dump_db_cmd = "mysqldump -h {host} -u {user} -p{password} {db_name}"
            restore_db_cmd = "mysql -h {host} -u {user} -p{password} {db_name}"
            dump_db_cmd = dump_db_cmd.format(
                host=TannerConfig.get("SQLI", "host"),
                user=TannerConfig.get("SQLI", "user"),
                password=TannerConfig.get("SQLI", "password"),
                db_name=user_db,
            )
            restore_db_cmd = restore_db_cmd.format(
                host=TannerConfig.get("SQLI", "host"),
                user=TannerConfig.get("SQLI", "user"),
                password=TannerConfig.get("SQLI", "password"),
                db_name=attacker_db,
            )
            try:
                dump_db_process = subprocess.Popen(dump_db_cmd, stdout=subprocess.PIPE, shell=True)
                restore_db_process = subprocess.Popen(restore_db_cmd, stdin=dump_db_process.stdout, shell=True)
                dump_db_process.stdout.close()
                dump_db_process.wait()
                restore_db_process.wait()
            except subprocess.CalledProcessError as e:
                self.logger.exception("Error during copying sql database : %s" % e)
        return attacker_db

    async def insert_dummy_data(self, table_name, data_tokens, cursor):
        """
        Inserts dummy data in the table based on input data tokens for ex: 'I,L'
        :param table_name (str): table in which data to be inserted
        :param data_tokens (str): input data format tokens
        :param cursor (object): current db cursor
        """

        inserted_data, token_list = self.generate_dummy_data(data_tokens)

        inserted_string_patt = "%s"
        if len(token_list) > 1:
            inserted_string_patt += ","
            inserted_string_patt *= len(token_list)
            inserted_string_patt = inserted_string_patt[:-1]

        await cursor.executemany("INSERT INTO " + table_name + " VALUES(" + inserted_string_patt + ")", inserted_data)

    async def create_query_map(self, db_name):
        """
        Returns a query map of the tables and its columns present in the database
        :param db_name (str): current database
        :return: query_map (dict): Created Query Map
        """

        query_map = {}
        tables = []
        conn = await self.connect_to_db()
        cursor = await conn.cursor()

        select_tables = "SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema= '{db_name}'"

        try:
            await cursor.execute(select_tables.format(db_name=db_name))
            result = await cursor.fetchall()
            for row in result:
                tables.append(row[0])
        except Exception as e:
            self.logger.exception("Error during query map creation")
        else:
            query_map = dict.fromkeys(tables)
            for table in tables:
                query = "SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE \
                table_name= '{table_name}' AND table_schema= '{db_name}'"

                columns = []
                try:
                    await cursor.execute(query.format(table_name=table, db_name=db_name))
                    result = await cursor.fetchall()
                    for row in result:
                        if row[7] == "int":
                            columns.append(dict(name=row[3], type="INTEGER"))
                        else:
                            columns.append(dict(name=row[3], type="TEXT"))
                    query_map[table] = columns
                except Exception:
                    self.logger.exception("Error during query map creation")
        return query_map
