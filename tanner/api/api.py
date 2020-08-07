import datetime
import logging
import operator
from asyncio import TimeoutError
from collections import ChainMap
from json import dumps, loads, JSONEncoder
from uuid import UUID

import psycopg2
from sqlalchemy.sql.expression import join
from sqlalchemy import select, func

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
        result["attack_frequency"] = {}
        async with self.pg_client.acquire() as conn:
            stmt = select(
                [PATHS.c.attack_type, func.count(PATHS.c.attack_type)]
            ).group_by(PATHS.c.attack_type)
            stmt = stmt.select_from(
                join(SESSIONS, PATHS, SESSIONS.c.id == PATHS.c.session_id)
            ).where(SESSIONS.c.sensor_id == snare_uuid)
            rows = await (await conn.execute(stmt)).fetchall()

            for r in rows:
                attack_type = AttackType(r[0]).name
                result["attack_frequency"][attack_type] = r[1]

            total_session_stmt = select(
                [func.count(SESSIONS.c.id)], distinct=True
            ).where(SESSIONS.c.sensor_id == snare_uuid)
            total_count = await (await conn.execute(total_session_stmt)).first()

            result["total_sessions"] = total_count[0]

            time_stmt = select(
                [func.sum(SESSIONS.c.end_time - SESSIONS.c.start_time)]
            ).where(SESSIONS.c.sensor_id == snare_uuid)

            times = await (await conn.execute(time_stmt)).fetchall()
            result["total_duration"] = str(times[0][0])

        return result

    async def return_session_info(self, sess_uuid):
        """This function returns information about single session.

        Args:
            sess_uuid (str): UUID of the session for which
                                the information has to be returned

        Returns:
            [dict]: Dictionary having infromation about the session.
        """
        try:
            UUID(sess_uuid)
        except ValueError:
            return {"Invalid SESSION UUID"}

        try:
            async with self.pg_client.acquire() as conn:
                stmt = select([SESSIONS]).where(SESSIONS.c.id == sess_uuid)
                query = await (await conn.execute(stmt)).fetchone()
                session = loads(dumps(dict(query), cls=AlchemyEncoder))

                cookies_query = select([COOKIES]).where(
                    COOKIES.c.session_id == sess_uuid
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
                    all_paths.append(dumps(dict(p), cls=AlchemyEncoder))
                session["paths"] = all_paths

                owners_query = select([OWNERS]).where(
                    OWNERS.c.session_id == session.get("id")
                )
                owners = await (await conn.execute(owners_query)).fetchall()

                owner_type = []
                for o in owners:
                    owner_type.append({o[1]: o[2]})
                session["owners"] = dict(ChainMap(*owner_type))
        except (
            TypeError,
            TimeoutError,
            psycopg2.ProgrammingError,
            psycopg2.OperationalError,
        ):
            session = {"error": "Invalid session ID"}

        return session

    async def return_snare_info(self, uuid, count, offset):
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
                stmt = (
                    select([SESSIONS])
                    .where(SESSIONS.c.sensor_id == uuid)
                    .offset(offset)
                    .limit(count)
                )
                query = await (await conn.execute(stmt)).fetchall()

                for row in query:
                    session = loads(dumps(dict(row), cls=AlchemyEncoder))
                    session_info = await self.return_session_info(session.get("id"))
                    query_res.append(session_info)
        except (
            ValueError,
            TimeoutError,
            psycopg2.ProgrammingError,
            psycopg2.OperationalError,
        ):
            query_res = "Invalid SNARE UUID"

        return query_res

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
        invalid_filters = []
        filter_list = [
            "attack_type",
            "owners",
            "start_time",
            "end_time",
            "peer_ip",
            "user_agent",
            "sensor_id",
        ]
        for fil in filters:
            if fil not in filter_list:
                invalid_filters.append(fil)

        if invalid_filters:
            results = "Invalid filters"
        else:
            stmt = self.apply_filters(filters)
            if stmt != "Invalid filter value":
                async with self.pg_client.acquire() as conn:
                    query = await (await conn.execute(stmt)).fetchall()

                    for row in query:
                        results.append(str(row[0]))
                results = list(set(results))
            else:
                results = stmt

        return results

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

        def check_time(time):
            """Check the format of the time passed in filters

            Args:
                time ([str]): Time in RFC format

            Returns:
                [str]: Time in humar readable format
            """
            try:
                formatted_time = datetime.datetime.strptime(time, "%d-%m-%YT%H:%M:%S")
            except ValueError:
                time = time + "T00:00:00"
                formatted_time = datetime.datetime.strptime(time, "%d-%m-%YT%H:%M:%S")

            return str(formatted_time)

        tables = "sessions S"
        columns = "S.id"
        where = "S.sensor_id='%s'" % (filters["sensor_id"][0])

        for parameter, values in filters.items():
            if parameter == "attack_type":
                tables += ", paths P"
                columns += ", P.session_id"
                for v in values:
                    try:
                        attack_type = AttackType[v].value
                        print(attack_type)
                        where += " AND P.attack_type=%s" % (attack_type)
                    except KeyError:
                        return "Invalid filter value"

                where += " AND S.id=P.session_id"
            if parameter == "owners":
                tables += ", owners O"
                columns += ", O.session_id"
                for v in values:
                    where += " AND O.owner_type='%s'" % (v)
                where += " AND S.id=O.session_id"
            if parameter == "start_time":
                for v in values:
                    start_time = check_time(v)
                    where += " AND S.start_time>='%s'" % (start_time)
            if parameter == "end_time":
                for v in values:
                    end_time = check_time(v)
                    where += " AND S.end_time<='%s'" % (end_time)
            if parameter == "peer_ip":
                for v in values:
                    where += " AND S.ip='%s'" % (v)
            if parameter == "user_agent":
                for v in values:
                    where += " AND S.user_agent='%s'" % (v)

        stmt = "SELECT %s FROM %s WHERE %s" % (columns, tables, where)
        return stmt
