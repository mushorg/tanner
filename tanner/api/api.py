import datetime
import logging
import operator
from asyncio import TimeoutError
from collections import ChainMap
from json import dumps, loads, JSONEncoder
from uuid import UUID

import psycopg2
from sqlalchemy import select

from tanner.dbutils import COOKIES, OWNERS, PATHS, SESSIONS
from tanner.utils.attack_type import AttackType


class AlchemyEncoder(JSONEncoder):
    def default(self, obj):
        """JSON encoder function for SQLAlchemy special classes.
            """
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, UUID):
            return str(obj)


class Api:
    def __init__(self, pg_client):
        self.logger = logging.getLogger("tanner.api.Api")
        self.pg_client = pg_client

    async def return_snares(self):
        """Returns a list of all the snares that are
        connected to the tanner.

        Returns:
            [list] -- List containing UUID of all snares
        """
        query_res = []

        async with self.pg_client.acquire() as conn:
            stmt = select([SESSIONS.c.sensor_id], distinct=True)
            rows = await (await conn.execute(stmt)).fetchall()
            for r in rows:
                query_res.append(str(r[0]))

        return query_res

    async def return_snare_stats(self, snare_uuid):
        """Returns the stats of the given snare

        Arguments:
            snare_uuid {uuid} -- UUID of snare

        Returns:
            [dict] -- Dictionary containing all stats snare.
        """
        result = {}
        result["total_sessions"] = 0
        result["total_duration"] = 0
        result["attack_frequency"] = {
            "sqli": 0,
            "lfi": 0,
            "xss": 0,
            "rfi": 0,
            "cmd_exec": 0,
        }
        async with self.pg_client.acquire() as conn:
            stmt = select([PATHS.c.attack_type])
            rows = await (await conn.execute(stmt)).fetchall()
            result["total_sessions"] = len(rows)
            for r in rows:
                attack_type = AttackType(r[0]).name
                if attack_type in result["attack_frequency"]:
                    result["attack_frequency"][attack_type] += 1

            time_stmt = select([SESSIONS.c.start_time, SESSIONS.c.end_time]).where(
                SESSIONS.c.sensor_id == snare_uuid
            )

            times = await (await conn.execute(time_stmt)).fetchall()

            for t in times:
                start = t[0].timestamp()
                end = t[1].timestamp()
                result["total_duration"] += end - start

        return result

    async def return_snare_info(self, uuid):
        """Returns JSON data that contains information about
         all the sessions a single snare instance have.

        Arguments:
            uuid [string] - Snare UUID
        """
        try:
            # generates a ValueError if invalid UUID is given
            UUID(uuid)

            query_res = []
            async with self.pg_client.acquire() as conn:
                stmt = select([SESSIONS]).where(SESSIONS.c.sensor_id == uuid)
                query = await (await conn.execute(stmt)).fetchall()

                for row in query:
                    session = loads(dumps(dict(row), default=alchemyencoder))

                    cookies_query = select([COOKIES]).where(
                        COOKIES.c.session_id == session.get("id")
                    )
                    cookies = await (await conn.execute(cookies_query)).fetchall()

                    all_cookies = []
                    for r in cookies:
                        all_cookies.append({r[1]: r[2]})
                    session["cookies"] = dict(ChainMap(*all_cookies))

                    paths_query = select([PATHS]).where(
                        PATHS.c.session_id == session.get("id")
                    )
                    paths = await (await conn.execute(paths_query)).fetchall()

                    all_paths = []
                    for p in paths:
                        all_paths.append(dumps(dict(p), default=alchemyencoder))
                    session["paths"] = all_cookies

                    owners_query = select([OWNERS]).where(
                        OWNERS.c.session_id == session.get("id")
                    )
                    owners = await (await conn.execute(owners_query)).fetchall()

                    owner_type = []
                    for o in owners:
                        owner_type.append({o[1]: o[2]})
                    session["owners"] = dict(ChainMap(*owner_type))

                    query_res.append(session)
        except (
            ValueError,
            TimeoutError,
            psycopg2.ProgrammingError,
            psycopg2.OperationalError,
        ):
            query_res = "Invalid SNARE UUID"

        return query_res

    async def return_session_info(self, sess_uuid, snare_uuid=None):
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_snares()
    async def return_sessions(self, filters):
        """Returns the list of all the sessions.
        Uses apply_filters function in this class
        to make the query accordingly.

        Args:
            filters (dict): all the filters that is to be applied

        Returns:
            [list]: list of sessions
        """
        results = []
        stmt = self.apply_filters(filters)
        async with self.pg_client.acquire() as conn:
            query = await (await conn.execute(stmt)).fetchall()

            for row in query:
                results.append(str(row[0]))
        
        return list(set(results))


    async def return_latest_session(self):
        latest_time = -1
        latest_session = None
        snares = await self.return_snares()
        try:
            for snare in snares:
                filters = {"snare_uuid": snare}
                sessions = await self.return_sessions(filters)
                for session in sessions:
                    if latest_time < session["end_time"]:
                        latest_time = session["end_time"]
                        latest_session = session["sess_uuid"]
        except TypeError:
            return None
        return latest_session

    def apply_filters(self, filters):
        """Makes SQL query according to the give filters

        Args:
            filters (dict): all the filters that is to be applied

        Returns:
            [str]: A sql query in string format
        """
        tables = "sessions S"
        columns = "S.id"
        where = "S.sensor_id='%s'"%(filters["sensor_id"])

        if "attack_type" in filters:
            tables += ", paths P"
            columns += ", P.session_id"
            where += " AND P.attack_type=%s"%(filters["attack_type"])
        elif "owners" in filters:
            tables += ", owners O"
            columns += ", O.session_id"
            where += " AND O.owner_type='%s'"%(filters["owners"])
        elif "start_time" in filters:
            where += " AND S.start_time=%s"%(filters["start_time"])
        elif "end_time" in filters:
            where += " AND S.end_time=%s"%(filters["end_time"])
        elif "peer_ip" in filters:
            where += " ANDS.ip='%s'"%(filters["peer_ip"])
        elif "user_agent" in filters:
            where += " AND S.user_agent='%s'"%(filters["user_agent"])

        stmt = "SELECT %s FROM %s WHERE %s"%(columns, tables, where)
        return stmt
