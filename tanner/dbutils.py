import asyncio

import logging
from sqlalchemy.sql.ddl import CreateTable
from sqlalchemy.dialects.postgresql import UUID, INET, TIMESTAMP, FLOAT
from sqlalchemy import MetaData, Table, Column, Integer, String, ForeignKey
import psycopg2
from datetime import datetime
from tanner.utils.attack_type import AttackType


class DBUtils:
    @staticmethod
    async def create_data_tables(pg_client):
        """Create all the required tables in
            the postgres database

        Arguments:
            pg_client {aiopg.pool.Pool}
        """
        meta = MetaData()
        sessions = Table(
            'sessions', meta,
            Column('id', UUID(as_uuid=True), primary_key=True, unique=True),
            Column('sensor_id', UUID(as_uuid=True), primary_key=True, index=True, nullable=False),
            Column('ip', INET, nullable=False),
            Column('port', Integer, nullable=False),
            Column('country', String, nullable=True),
            Column('country_code', String, nullable=True),
            Column('city', String, nullable=True),
            Column('zip_code', Integer, nullable=True),
            Column('user_agent', String, nullable=False),
            Column('start_time', TIMESTAMP, nullable=False),
            Column('end_time', TIMESTAMP, nullable=False),
            Column('rps', FLOAT, nullable=False, comment='requests per second'),
            Column('atbr', FLOAT, nullable=False, comment='approx_time_between_requests'),
            Column('accepted_paths', Integer, nullable=False),
            Column('errors', Integer, nullable=False),
            Column('hidden_links', Integer, nullable=False),
            Column('referer', String, nullable=False),

        )

        paths = Table(
            'paths', meta,
            Column('session_id', UUID(as_uuid=True), ForeignKey('sessions.id'), index=True),
            Column('path', String, nullable=False),
            Column('created_at', TIMESTAMP),
            Column('response_status', Integer, nullable=False),
            Column('attack_type', Integer, nullable=False)
        )
        cookies = Table(
            'cookies', meta,
            Column('session_id', UUID(as_uuid=True), ForeignKey('sessions.id'), index=True),
            Column('key', String),
            Column('value', String)
        )
        owners = Table(
            'owners', meta,
            Column('session_id', UUID(as_uuid=True), ForeignKey('sessions.id'), index=True),
            Column('owner_type', String),
            Column('probability', FLOAT)
        )
        async with pg_client.acquire() as conn:
            await conn.execute('DROP TABLE IF EXISTS cookies')
            await conn.execute('DROP TABLE IF EXISTS paths')
            await conn.execute('DROP TABLE IF EXISTS owners')
            await conn.execute('DROP TABLE IF EXISTS sessions')
            await conn.execute(CreateTable(sessions))
            await conn.execute(CreateTable(paths))
            await conn.execute(CreateTable(cookies))
            await conn.execute(CreateTable(owners))

    @staticmethod
    async def add_analyzed_data(session, pg_client):
        """Insert analyzed sessions into postgres

        Arguments:
            session {dict} -- dictionary having all the sessions details
            pg_client {aiopg.pool.Pool}
        """

        def time_convertor(time):
            """Convert the epoch time to the postgres
            timestamp format

            Arguments:
                time {str} -- time in epoch format
            """
            return datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')

        Cookies = "INSERT INTO cookies(session_id, key, value) VALUES('{uuid}', '{key}', '{value}');"
        Sessions = (
            "INSERT INTO sessions (id, sensor_id, ip, port, country,"
            "country_code, city, zip_code, user_agent, start_time,"
            "end_time, rps, atbr, accepted_paths, errors, hidden_links, referer) "
            "VALUES ('{uuid}','{sensor}','{ip}',{port},'{country}',"
            "'{ccode}','{city}',{zcode},'{ua}','{st}','{et}',{rps},"
            "{atbr},{apaths},{err},{hlinks},'{referer}');"
        )
        Paths = (
            "INSERT INTO paths (session_id, path, created_at, response_status, attack_type) "
            "VALUES ('{id}','{path}','{time}',{res},{atype});"
        )
        Owners = (
            "INSERT INTO owners (session_id, owner_type, probability) "
            "VALUES ('{id}', '{key}', {val});"
        )

        start_time = time_convertor(session["start_time"])
        end_time = time_convertor(session["end_time"])

        logger = logging.getLogger(__name__)

        try:
            sessions_query = Sessions.format(
                uuid=session["sess_uuid"],
                sensor=session["snare_uuid"],
                ip=session["peer_ip"],
                port=session["peer_port"],
                country=session["location"]["country"],
                ccode=session["location"]["country_code"],
                city=session["location"]["city"],
                zcode=session["location"]["zip_code"],
                ua=session["user_agent"],
                st=start_time,
                et=end_time,
                rps=session["requests_in_second"],
                atbr=session["approx_time_between_requests"],
                apaths=session["accepted_paths"],
                err=session["errors"],
                hlinks=session["hidden_links"],
                referer=session["referer"]
            )

            async with pg_client.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sessions_query)
                    for k, v in session["cookies"].items():
                        await cur.execute(
                            Cookies.format(uuid=session["sess_uuid"], key=k, value=v)
                        )

                    for path in session["paths"]:
                        timestamp = time_convertor(path["timestamp"])
                        paths_query = Paths.format(
                            id=session["sess_uuid"],
                            path=path["path"],
                            time=timestamp,
                            res=path["response_status"],
                            atype=AttackType[path["attack_type"]].value
                        )

                        await cur.execute(paths_query)

                    for k, v in session["possible_owners"].items():
                        await cur.execute(Owners.format(id=session["sess_uuid"], key=k, val=v))

                cur.close()
            conn.close()

        except psycopg2.ProgrammingError as pg_error:
            logger.exception(
                "Error with Postgres. Session not added to postgres: %s",
                pg_error,
            )
