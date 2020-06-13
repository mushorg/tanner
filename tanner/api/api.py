import json
import logging
import operator
import psycopg2
from asyncio import TimeoutError
from uuid import UUID
from collections import ChainMap
from tanner.utils.attack_type import AttackType


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
            async with conn.cursor() as cur:
                await cur.execute("SELECT DISTINCT sensor_id FROM sessions")
                ans = await cur.fetchall()
                for r in ans:
                    query_res.append(str(r[0]))
            cur.close()
        conn.close()
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

        sessions = await self.return_snare_info(snare_uuid)
        if sessions == "Invalid SNARE UUID":
            return result

        result["total_sessions"] = len(sessions)
        for sess in sessions:
            result["total_duration"] += sess["end_time"] - sess["start_time"]
            for path in sess["paths"]:
                if path["attack_type"] in result["attack_frequency"]:
                    result["attack_frequency"][path["attack_type"]] += 1

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
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                    SELECT * FROM sessions
                    WHERE
                        sessions.sensor_id = '%s'
                    """
                        % (uuid)
                    )
                    while True:
                        session = await cur.fetchmany(size=200)

                        if not session:
                            break

                        for r in session:
                            sess = {
                                "sess_uuid": str(r[0]),
                                "snare_uuid": str(r[1]),
                                "ip": r[2],
                                "port": r[3],
                                "location": {
                                    "country": r[4],
                                    "country_code": r[5],
                                    "city": r[6],
                                    "zip_code": r[7],
                                },
                                "user_agent": r[8],
                                "start_time": r[9].timestamp(),
                                "end_time": r[10].timestamp(),
                                "request_per_second": r[11],
                                "approx_time_between_requests": r[12],
                                "accepted_paths": r[13],
                                "errors": r[14],
                                "hidden_links": r[15],
                                "referrer": r[16],
                            }

                            # Extracting all cookies
                            await cur.execute(
                                """
                            SELECT * FROM cookies WHERE cookies.session_id = '%s'
                            """
                                % (str(r[0]))
                            )

                            while True:
                                cookies = await cur.fetchmany(size=200)

                                if not cookies:
                                    break

                                all_cookies = []
                                for r in cookies:
                                    all_cookies.append({r[1]: r[2]})
                            sess["cookies"] = dict(ChainMap(*all_cookies))

                            # Extracting all paths
                            await cur.execute(
                                """
                            SELECT * FROM paths WHERE paths.session_id = '%s'
                            """
                                % (str(r[0]))
                            )

                            while True:
                                paths = await cur.fetchmany(size=200)

                                if not paths:
                                    break
                                all_paths = []

                                for p in paths:
                                    all_paths.append(
                                        {
                                            "path": p[1],
                                            "timestamp": p[2].timestamp(),
                                            "response_status": p[3],
                                            "attack_type": AttackType(p[4]).name,
                                        }
                                    )
                            sess["paths"] = all_paths

                            # Extracting all owners
                            await cur.execute(
                                """
                            SELECT * FROM owners WHERE owners.session_id = '%s'
                            """
                                % (str(r[0]))
                            )

                            while True:
                                owners = await cur.fetchmany(size=200)

                                if not owners:
                                    break
                                owner_type = []

                                for o in owners:
                                    owner_type.append({o[1]: o[2]})
                            sess["owners"] = dict(ChainMap(*owner_type))
                            query_res.append(sess)
                    cur.close()
            conn.close()
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
                if sess["sess_uuid"] == sess_uuid:
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
            "snare_uuid": operator.eq,
            "location": operator.contains,
        }

        try:
            if available_filters[filter_name] is operator.contains:
                return available_filters[filter_name](sess[filter_name], filter_value)
            else:
                return available_filters[filter_name](filter_value, sess[filter_name])
        except KeyError:
            raise
