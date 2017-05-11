import asyncio

from tanner.utils import mysql_db_helper
from tanner import config


class MySQLIEmulator:
	def __init__(self, working_dir, db_name):
		self.db_name = db_name
		self.helper = mysql_db_helper.MySQLDBHelper()

	async def setup_db(self, query_map):
		db_exists = await self.helper.check_db_exists(self.db_name)
		if not db_exists:
			await self.helper.setup_db_from_config(self.db_name)
		query_map = await self.helper.create_query_map(self.db_name)
		return query_map

	async def create_attacker_db(self, session):
		attacker_db_name = 'attacker_' + session.sess_uuid.hex
		attacker_db = await self.helper.copy_db(self.db_name,
												attacker_db_name
												)
		session.associate_db(attacker_db)
		return attacker_db

	async def execute_query(self, query, db_name):
		result = []
		conn = await self.helper.connect_to_db()
		cursor = await conn.cursor()
		await cursor.execute('USE {db_name}'.format(db_name=db_name))
		try:
			await cursor.execute(query)
			rows = await cursor.fetchall()
			for row in rows:
				result.append(list(row))
		except Exception as mysql_error:
			result = str(mysql_error)
		return result