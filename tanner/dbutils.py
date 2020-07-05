import asyncio
import logging
from datetime import datetime

import psycopg2
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    insert,
    inspect,
)
from sqlalchemy.dialects.postgresql import FLOAT, INET, TIMESTAMP, UUID
from sqlalchemy.sql.ddl import CreateTable

from tanner.utils.attack_type import AttackType

meta = MetaData()
SESSIONS = Table(
    "sessions",
    meta,
    Column("id", UUID(as_uuid=True), primary_key=True, unique=True),
    Column(
        "sensor_id", UUID(as_uuid=True), primary_key=True, index=True, nullable=False
    ),
    Column("ip", INET, nullable=False),
    Column("port", Integer, nullable=False),
    Column("country", String, nullable=True),
    Column("country_code", String, nullable=True),
    Column("city", String, nullable=True),
    Column("zip_code", Integer, nullable=True),
    Column("user_agent", String, nullable=False),
    Column("start_time", TIMESTAMP, nullable=False),
    Column("end_time", TIMESTAMP, nullable=False),
    Column("rps", FLOAT, nullable=False, comment="requests per second"),
    Column("atbr", FLOAT, nullable=False, comment="approx_time_between_requests"),
    Column("accepted_paths", Integer, nullable=False),
    Column("errors", Integer, nullable=False),
    Column("hidden_links", Integer, nullable=False),
    Column("referer", String),
)

PATHS = Table(
    "paths",
    meta,
    Column("session_id", UUID(as_uuid=True), ForeignKey("sessions.id"), index=True),
    Column("path", String, nullable=False),
    Column("created_at", TIMESTAMP),
    Column("response_status", Integer, nullable=False),
    Column("attack_type", Integer, nullable=False),
)
COOKIES = Table(
    "cookies",
    meta,
    Column("session_id", UUID(as_uuid=True), ForeignKey("sessions.id"), index=True),
    Column("key", String),
    Column("value", String),
)
OWNERS = Table(
    "owners",
    meta,
    Column("session_id", UUID(as_uuid=True), ForeignKey("sessions.id"), index=True),
    Column("owner_type", String),
    Column("probability", FLOAT),
)


class DBUtils:
    @staticmethod
    async def create_data_tables(pg_client):
        """Create all the required tables in
            the postgres database

        Arguments:
            pg_client {aiopg.sa.engine.Engine}
        """
        Tables = [SESSIONS, PATHS, COOKIES, OWNERS]

        async with pg_client.acquire() as conn:
            for table in Tables:
                try:
                    await conn.execute(CreateTable(table))
                except psycopg2.errors.DuplicateTable:
                    continue

    @staticmethod
    async def add_analyzed_data(session, pg_client):
        """Insert analyzed sessions into postgres

        Arguments:
            session {dict} -- dictionary having all the sessions details
            pg_client {aiopg.sa.engine.Engine}
        """

        def time_convertor(time):
            """Convert the epoch time to the postgres
            timestamp format

            Arguments:
                time {str} -- time in epoch format
            """
            return datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M:%S")

        start_time = time_convertor(session["start_time"])
        end_time = time_convertor(session["end_time"])

        logger = logging.getLogger(__name__)

        try:
            async with pg_client.acquire() as conn:
                await conn.execute(
                    SESSIONS.insert(),
                    id=session["sess_uuid"],
                    sensor_id=session["snare_uuid"],
                    ip=session["peer_ip"],
                    port=session["peer_port"],
                    country=session["location"]["country"],
                    country_code=session["location"]["country_code"],
                    city=session["location"]["city"],
                    zip_code=session["location"]["zip_code"],
                    user_agent=session["user_agent"],
                    start_time=start_time,
                    end_time=end_time,
                    rps=session["requests_in_second"],
                    atbr=session["approx_time_between_requests"],
                    accepted_paths=session["accepted_paths"],
                    errors=session["errors"],
                    hidden_links=session["hidden_links"],
                    referer=session["referer"],
                )

                for k, v in session["cookies"].items():
                    await conn.execute(
                        COOKIES.insert(),
                        session_id=session["sess_uuid"],
                        key=k,
                        value=v,
                    )

                for path in session["paths"]:
                    timestamp = time_convertor(path["timestamp"])
                    try:
                        attackType = AttackType[path["attack_type"]].value
                    except KeyError:
                        attackType = 0
                    await conn.execute(
                        PATHS.insert(),
                        session_id=session["sess_uuid"],
                        path=path["path"],
                        created_at=timestamp,
                        response_status=path["response_status"],
                        attack_type=attackType,
                    )

                for k, v in session["possible_owners"].items():
                    await conn.execute(
                        insert(OWNERS).values(
                            session_id=session["sess_uuid"], owner_type=k, probability=v
                        )
                    )

        except psycopg2.ProgrammingError as pg_error:
            logger.exception(
                "Error with Postgres. Session not added to postgres: %s", pg_error,
            )
