import datetime
import logging
import operator
from asyncio import TimeoutError
from collections import ChainMap
from json import dumps, loads
from uuid import UUID

import psycopg2
from sqlalchemy import select

from tanner.dbutils import COOKIES, OWNERS, PATHS, SESSIONS
from tanner.utils.attack_type import AttackType


def alchemyencoder(obj):
    """JSON encoder function for SQLAlchemy special classes."""
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

        for snare_id in snare_uuids:
            sessions = await self.return_snare_info(snare_id)
            if sessions == "Invalid SNARE UUID":
                continue
            for sess in sessions:
                if sess["id"] == sess_uuid:
                    return sess

    async def return_sessions(self, filters):
        snare_uuids = await self.return_snares()

        matching_sessions = []
        for snare_id in snare_uuids:
            result = await self.return_snare_info(snare_id)
            if result == "Invalid SNARE UUID":
                return "Invalid filter : SNARE UUID"
            sessions = result
            for sess in sessions:
                match_count = 0
                for filter_name, filter_value in filters.items():
                    try:
                        if self.apply_filter(filter_name, filter_value, sess):
                            match_count += 1
                    except KeyError:
                        return "Invalid filter : %s" % filter_name

                if match_count == len(filters):
                    matching_sessions.append(sess)
        return matching_sessions

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

    def apply_filter(self, filter_name, filter_value, sess):
        available_filters = {
            "user_agent": operator.contains,
            "peer_ip": operator.eq,
            "attack_types": operator.contains,
            "possible_owners": operator.contains,
            "start_time": operator.le,
            "end_time": operator.ge,
            "sensor_id": operator.eq,
            "location": operator.contains,
        }

        try:
            if available_filters[filter_name] is operator.contains:
                return available_filters[filter_name](sess[filter_name], filter_value)
            else:
                return available_filters[filter_name](filter_value, sess[filter_name])
        except KeyError:
            raise
