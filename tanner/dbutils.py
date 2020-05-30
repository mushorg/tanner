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
                    "ip" INET NOT NULL,
                    "port" INT NOT NULL,
                    "country" TEXT NULL,
                    "country_code" TEXT NULL,
                    "city" TEXT NULL,
                    "zip_code" INT NULL,
                    "user_agent" TEXT NOT NULL,
                    "start_time" TIMESTAMP DEFAULT NOW(),
                    "end_time" TIMESTAMP DEFAULT NOW(),
                    "rps" FLOAT NOT NULL,
                    "atbr" FLOAT NOT NULL,
                    "accepted_paths" INT NOT NULL,
                    "errors" INT NOT NULL,
                    "hidden_links" INT NOT NULL,
                    "referer" TEXT NOT NULL
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
                    "owner_type" TEXT,
                    "probability" TEXT
                )
                """
                )
                await cur.execute(
                    "comment on column sessions.rps is 'requests per second'"
                )
                await cur.execute(
                    "comment on column sessions.atbr is 'approx_time_between_requests'"
                )
                await cur.execute("CREATE INDEX ON sessions(sensor_id)")
                await cur.execute('CREATE INDEX ON "paths"(session_id)')
                await cur.execute('CREATE INDEX ON "cookies"(session_id)')
                await cur.execute('CREATE INDEX ON "owners"(session_id)')
            cur.close()
        conn.close()


class InsertionQueries:
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
        "VALUES ('{id}', '{key}', '{val}');"
    )
