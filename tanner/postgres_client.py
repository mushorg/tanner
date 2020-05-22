import asyncio
import logging

import aiopg

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

            async with pg_client.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                    CREATE TABLE IF NOT EXISTS "paths" (
                        "sess_uuid" UUID PRIMARY KEY NOT NULL UNIQUE,
                        "path" TEXT NOT NULL,
                        "timestamp" TIMESTAMP NOT NULL,
                        "response_status" INT NOT NULL,
                        "attack_type" INT NOT NULL
                    )
                    """
                    )

                    await cur.execute(
                        """
                    CREATE TABLE IF NOT EXISTS "cookies" (
                        "sess_uuid" UUID PRIMARY KEY NOT NULL UNIQUE,
                        "key" TEXT NULL,
                        "value" TEXT NULL
                    )
                    """
                    )

                    await cur.execute(
                        """
                    CREATE TABLE IF NOT EXISTS "session_data" (
                        "sess_uuid" UUID NOT NULL PRIMARY KEY,
                        "snare_uuid" TEXT NOT NULL,
                        "peer.ip" INET NOT NULL,
                        "peer.port" INT NOT NULL,
                        "location.country" TEXT NULL,
                        "location.country_code" TEXT NULL,
                        "location.city" TEXT NULL,
                        "location.zip_code" INT NULL,
                        "user_agent" TEXT NOT NULL,
                        "start_time" TIMESTAMP,
                        "end_time" TIMESTAMP,
                        "requests_in_second" FLOAT NULL,
                        "approx_time_between_requests" FLOAT NULL,
                        "accepted_paths" INT NULL,
                        "errors" INT NULL,
                        "hidden_links" INT NULL,
                        "paths" UUID REFERENCES "paths"(sess_uuid),
                        "cookies" UUID REFERENCES "cookies"(sess_uuid),
                        "referer" TEXT NULL,
                        "possible_owners.user" FLOAT NULL,
                        "possible_owners.type" FLOAT NULL,
                        "possible_owners.tool" FLOAT NULL,
                        "possible_owners.crawler" FLOAT NULL
                        )
                    """
                    )
                    await cur.execute("CREATE INDEX ON session_data(sess_uuid)")
                    await cur.execute("CREATE INDEX ON session_data(snare_uuid)")
                    await cur.execute('CREATE INDEX ON "paths"(sess_uuid)')
                    await cur.execute('CREATE INDEX ON "cookies"(sess_uuid)')
                cur.close()
            conn.close()
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception("Failed to connect to postgres {}".format(timeout_error))
            exit()
        return pg_client
