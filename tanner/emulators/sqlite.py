import os
import sqlite3
import logging

from tanner.utils import sqlite_db_helper


class SQLITEEmulator:
    def __init__(self, db_name, working_dir):
        self.logger = logging.getLogger("tanner.sqlite_emulator")
        self.db_name = db_name
        self.working_dir = os.path.join(working_dir, "db/")
        self.helper = sqlite_db_helper.SQLITEDBHelper()

    async def setup_db(self):
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)
        db = os.path.join(self.working_dir, self.db_name)
        if not os.path.exists(db):
            await self.helper.setup_db_from_config(self.working_dir, self.db_name)
        query_map = self.helper.create_query_map(self.working_dir, self.db_name)
        return query_map

    async def create_attacker_db(self, session):
        attacker_db_name = "attacker_" + session.sess_uuid.hex
        attacker_db = self.helper.copy_db(self.db_name, attacker_db_name, self.working_dir)
        session.associate_db(attacker_db)
        return attacker_db

    async def execute_query(self, query, db):
        result = []
        conn = sqlite3.connect(db)
        cursor = conn.cursor()
        try:
            for row in cursor.execute(query):
                result.append(list(row))
        except sqlite3.OperationalError as sqlite_error:
            self.logger.debug("Error while executing query: %s", sqlite_error)
            result = str(sqlite_error)
        return result
