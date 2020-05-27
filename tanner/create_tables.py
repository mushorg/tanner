import asyncio


class CreateTables:
    @staticmethod
    async def create_data_tables(pg_client):
        """Create all the required tables in
            the postgres database

        Arguments:
            pg_client {aiopg.pool.Pool}
        """
        async with pg_client.acquire() as conn:
            async with conn.cursor() as cur:

                await cur.execute(
                    """
                CREATE TABLE IF NOT EXISTS "sessions" (
                    "id" UUID PRIMARY KEY,
                    "sensor_id" UUID NOT NULL,
                    "peer.ip" INET NOT NULL,
                    "peer.port" INT NOT NULL,
                    "location.country" TEXT NULL,
                    "location.country_code" TEXT NULL,
                    "location.city" TEXT NULL,
                    "location.zip_code" INT NULL,
                    "user_agent" TEXT NOT NULL,
                    "start_time" TIMESTAMP DEFAULT NOW(),
                    "end_time" TIMESTAMP DEFAULT NOW(),
                    "rps" FLOAT NULL,
                    "approx_time_between_requests" FLOAT NULL,
                    "accepted_paths" INT NULL,
                    "errors" INT NULL,
                    "hidden_links" INT NULL,
                    "referer" TEXT NULL
                    )
                """
                )
                await cur.execute(
                    """
                CREATE TABLE IF NOT EXISTS "paths" (
                    "session_id" UUID REFERENCES sessions(id),
                    "path" TEXT NOT NULL,
                    "created_at" TIMESTAMP DEFAULT now(),
                    "response_status" INT NOT NULL,
                    "attack_type" INT NOT NULL
                )
                """
                )

                await cur.execute(
                    """
                CREATE TABLE IF NOT EXISTS "cookies" (
                    "session_id" UUID REFERENCES sessions(id),
                    "key" TEXT NULL,
                    "value" TEXT NULL
                )
                """
                )
                await cur.execute(
                    """
                CREATE TABLE IF NOT EXISTS "owners" (
                    "session_id" UUID REFERENCES sessions(id),
                    "key" TEXT,
                    "value" TEXT
                )
                """
                )
                await cur.execute("comment on column sessions.rps is 'requests per second'")
                await cur.execute("CREATE INDEX ON sessions(sensor_id)")
                await cur.execute('CREATE INDEX ON "paths"(session_id)')
                await cur.execute('CREATE INDEX ON "cookies"(session_id)')
                await cur.execute('CREATE INDEX ON "owners"(session_id)')
            cur.close()
        conn.close()
