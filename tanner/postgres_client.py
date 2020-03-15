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
            postgres_client = await asyncio.wait_for(aiopg.create_pool(db_string, maxsize = poolsize),
                              timeout = int(timeout))
            with(await postgres_client.cursor()) as cur:
                await cur.execute("CREATE TABLE IF NOT EXISTS tanner(key text PRIMARY KEY, dict JSONB)")
                # cur.close()
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception("Failed to connect to postgres {}".format(timeout_error))
            exit()
        return postgres_client

        async def add_postgres_session(self, raw_data, postgres_client):
            async with postgres_client.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('SELECT key FROM tanner')
                    keys_get=await cur.fetchall()
                    keys=[]
                    for temp in keys_get:
                        keys.append(temp[0])
                    print(keys)
                    if keys:
                        if 'snare_ids' in keys:
                            # accessing previous daata
                            await cur.execute("SELECT dict FROM tanner WHERE key=%s",['snare_ids'])
                            row=await cur.fetchone()
                            previous_data=row[0]['snare_ids']
                            required_dict=dict(snare_ids=previous_data)
                            required_dict['snare_ids'].append(valid_data['uuid'])
                            await cur.execute("UPDATE tanner SET dict=%s WHERE key=%s", [Json(required_dict),'snare_ids'])
                        else:
                            # creating new data
                            required_dict=dict(snare_ids=[valid_data['uuid']])
                            await cur.execute('INSERT INTO tanner(key,dict) VALUES(%s,%s)', ['snare_ids',Json(required_dict)])
                    else:
                        # creating first commit
                        required_dict=dict(snare_ids=[valid_data['uuid']])
                        await cur.execute('INSERT INTO tanner(key,dict) VALUES(%s,%s)', ['snare_ids',Json(required_dict)])
                    await cur.close()
                await conn.close()
            print('Done')
            return True

        async def delete_postgres_session(self, session_id, postgres_client):
            async with postgres_client.curssor() as cur:
                await cur.execute("DELETE FROM tanner WHERE key=%s",[session_id])
                await cur.close()
            return True

        async def update_postgres_session(self, session_id, new_data, postgres_client):
            async with postgres_client.cursor() as cur:
                updated_data={'{}'.format(session_id):[new_data]}
                await cur.execute("UPDATE tanner SET dict=%s WHERE key=%s", [Json(updated_data), session_id])
                cur.close()
            return True
