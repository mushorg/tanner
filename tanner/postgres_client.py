import asyncio
import logging

import aiopg
import psycopg2

from tanner.config import TannerConfig

LOGGER = logging.getLogger(__name__)


class PostgresClient:
    def __init__(self):
        self.logger = logging.getLogger("tanner.db_helper.postgres")

        self.host = TannerConfig.get("POSTGRES", "host")
        self.port = TannerConfig.get("POSTGRES", "port")
        self.user = TannerConfig.get("POSTGRES", "user")
        self.password = TannerConfig.get("POSTGRES", "password")
        self.db_name = TannerConfig.get("POSTGRES", "db_name")
        self.poolsize = TannerConfig.get("POSTGRES", "poolsize")
        self.timeout = TannerConfig.get("POSTGRES", "timeout")

    async def get_pg_client(self):
        pg_client = None
        try:
            dsn = "dbname={} user={} password={} host={} port={}".format(
                self.db_name, self.user, self.password, self.host, self.port
            )

            pg_client = await asyncio.wait_for(
                aiopg.create_pool(dsn, maxsize=self.poolsize), timeout=int(self.timeout)
            )
        except (
            asyncio.TimeoutError,
            psycopg2.ProgrammingError,
            psycopg2.OperationalError
        ) as error:
            LOGGER.exception("Failed to connect to postgres {}".format(error))
            exit()
        return pg_client
