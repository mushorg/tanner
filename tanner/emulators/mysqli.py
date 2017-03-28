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
		self.query_map = None

	@asyncio.coroutine
	def setup_db(self):
		if not self.helper.check_db_exists(self.db_name):
			yield from self.helper.setup_db_from_config(self.db_name)
		if self.query_map is None:
			self.query_map = yield from self.helper.create_query_map(self.db_name)


if __name__ == '__main__':
	sqli = MySQLIEmulator('/opt/tanner', 'tanner_db')
	loop = asyncio.get_event_loop()
	result = loop.run_until_complete(sqli.setup_db())

