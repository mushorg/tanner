import asyncio
import pymysql
import os
import urllib.parse
import pylibinjection
from asyncio.subprocess import PIPE

from tanner.utils import mysql_db_helper
from tanner import config


class MySQLIEmulator:
	def __init__(self, working_dir, db_name):
		self.db_name = db_name
		self.helper = mysql_db_helper.MySQLDBHelper()
		self.working_dir = os.path.join(working_dir, 'db/')
		self.query_map = None

	@asyncio.coroutine
	def setup_db(self):
		conn = pymysql.connect(host='localhost', user='root', password='***********')
		cursor = conn.cursor()
		check_DB_exists_query = 'SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = \'{}\''.format(self.db_name)
		if not cursor.execute(check_DB_exists_query):
			yield from self.helper.setup_db_from_config(conn, self.db_name)
		if self.query_map is None:
			self.query_map = yield from self.helper.create_query_map(conn, self.db_name)
		conn.close()


# if __name__ == '__main__':
# 	sqli = MySQLIEmulator('/opt/tanner', 'tanner_db')
# 	loop = asyncio.get_event_loop()
# 	result = loop.run_until_complete(sqli.setup_db())

