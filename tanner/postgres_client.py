import asyncio
import logging
from sqlalchemy import create_engine
import aiopg
from tanner.config import TannerConfig

LOGGER = logging.getLogger(__name__)


class PostgresClient:
    async def get_postgres_client():
        postgres_client = None
        try:
            host = TannerConfig.get('POSTGRES', 'host')
            port = TannerConfig.get('POSTGRES', 'port')
            dbname = TannerConfig.get('POSTGRES', 'db_name')
            user = TannerConfig.get('POSTGRES', 'user')
            timeout = TannerConfig.get('POSTGRES', 'timeout')
            password = TannerConfig.get('POSTGRES', 'password')
            poolsize = TannerConfig.get('POSTGRES', 'poolsize')
            if poolsize is None:
                poolsize = TannerConfig.get('REDIS', 'poolsize')
            db_string = 'dbname={} user={} password={} host={} port={}'.format(dbname, user, password, host, port)
            postgres_client = await asyncio.wait_for(aiopg.create_pool(db_string, maxsize = poolsize), timeout = int(timeout))
            async with postgres_client.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("CREATE TABLE IF NOT EXISTS tanner(uuid TEXT, dict JSONB)")
                    cur.close()
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception("Failed to connect to postgres {}".format(timeout_error))
            exit()
        return postgres_client
