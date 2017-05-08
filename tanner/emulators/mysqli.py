import asyncio

from tanner.utils import mysql_db_helper
from tanner import config


class MySQLIEmulator:
	def __init__(self, working_dir, db_name):
		self.db_name = db_name
		self.helper = mysql_db_helper.MySQLDBHelper()

	@asyncio.coroutine
	def setup_db(self, query_map):
		db_exists = yield from self.helper.check_db_exists(self.db_name)
		if not db_exists:
			yield from self.helper.setup_db_from_config(self.db_name)
		query_map = yield from self.helper.create_query_map(self.db_name)
		return query_map

	@asyncio.coroutine
	def create_attacker_db(self, session):
		attacker_db_name = 'attacker_' + session.sess_uuid.hex
		attacker_db = yield from self.helper.copy_db(self.db_name,
													 attacker_db_name
													 )
		session.associate_db(attacker_db)
		return attacker_db

	@asyncio.coroutine
	def execute_query(self, query, db_name):
		result = []
		conn = yield from self.helper.connect_to_db()
		cursor = yield from conn.cursor()
		yield from cursor.execute('USE {db_name}'.format(db_name=db_name))
		try:
			yield from cursor.execute(query)
			rows = yield from cursor.fetchall()
			for row in rows:
				result.append(list(row))
		except Exception as mysql_error:
			result = str(mysql_error)
		return result