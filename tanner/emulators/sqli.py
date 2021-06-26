import logging
import pylibinjection

from tanner.config import TannerConfig
from tanner.emulators import mysqli, sqlite


class SqliEmulator:
    def __init__(self, db_name, working_dir):
        self.logger = logging.getLogger("tanner.sqli_emulator")
        if TannerConfig.get("SQLI", "type") == "MySQL":
            self.sqli_emulator = mysqli.MySQLIEmulator(db_name)
        else:
            self.sqli_emulator = sqlite.SQLITEEmulator(db_name, working_dir)

        self.query_map = None

    def scan(self, value):
        detection = None
        payload = bytes(value, "utf-8")
        sqli = pylibinjection.detect_sqli(payload)
        if int(sqli["sqli"]):
            detection = dict(name="sqli", order=2)
        return detection

    def map_query(self, attack_value):
        db_query = None
        param = attack_value["id"]
        param_value = attack_value["value"].replace("'", " ")
        tables = []
        for table, columns in self.query_map.items():
            for column in columns:
                if param == column["name"]:
                    tables.append(dict(table_name=table, column=column))

        if tables:
            if tables[0]["column"]["type"] == "INTEGER":
                db_query = "SELECT * from " + tables[0]["table_name"] + " WHERE " + param + "=" + param_value + ";"
            else:
                db_query = "SELECT * from " + tables[0]["table_name"] + " WHERE " + param + '="' + param_value + '";'

        return db_query

    async def get_sqli_result(self, attack_value, attacker_db):
        db_query = self.map_query(attack_value)
        if db_query is None:
            if TannerConfig.get("SQLI", "type") == "MySQL":
                error_result = "You have an error in your SQL syntax; check the manual\
                                that corresponds to your MySQL server version for the\
                                right syntax to use near {} at line 1".format(
                    attack_value["id"]
                )
            else:
                error_result = "SQL ERROR: near {}: syntax error".format(attack_value["id"])

            self.logger.debug("Error while executing: %s", error_result)
            result = dict(value=error_result, page=True)
        else:
            execute_result = await self.sqli_emulator.execute_query(db_query, attacker_db)
            if isinstance(execute_result, list):
                execute_result = " ".join([str(x) for x in execute_result])
            result = dict(value=execute_result, page=True)
        return result

    async def handle(self, attack_params, session):
        if self.query_map is None:
            self.query_map = await self.sqli_emulator.setup_db()
        attacker_db = await self.sqli_emulator.create_attacker_db(session)
        result = await self.get_sqli_result(attack_params[0], attacker_db)
        return result
