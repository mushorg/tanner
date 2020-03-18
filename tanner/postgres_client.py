import asyncio
import logging
from sqlalchemy import create_engine
from psycopg2.extras import Json
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
            async with postgres_client.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("CREATE TABLE IF NOT EXISTS tanner(key text PRIMARY KEY, dict JSONB)")
                    cur.close()
                conn.close()
        except asyncio.TimeoutError as timeout_error:
            LOGGER.exception("Failed to connect to postgres {}".format(timeout_error))
            exit()
        return postgres_client


    async def add_postgres_session(self, valid_data, postgres_client):
        print('herer')
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute('SELECT key FROM tanner')
                keys_get=await cur.fetchall()
                keys=[]
                for temp in keys_get:
                    keys.append(temp[0])
                print('Keys: ',keys)

                await asyncio.sleep(0.0002)

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
                    print("done")
                cur.close()
            conn.close()
        print('Done')
        return True
    async def delete_postgres_session(session_id, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.curssor() as cur:
                await cur.execute("DELETE FROM tanner WHERE key=%s",[session_id])
                cur.close()
            conn.close()
        return True

    async def update_postgres_session(session_id, new_data, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                updated_data={'{}'.format(session_id):[new_data]}
                await cur.execute("UPDATE tanner SET dict=%s WHERE key=%s", [Json(updated_data), session_id])
                cur.close()
            conn.close()
        return True

    async def get(self, session_id, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT dict FROM tanner WHERE key=%s",[session_id])
                data = await cur.fetchone()
                cur.close()
            conn.close()
        return data

    async def set(self, key, value, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("INSERT INTO tanner(key, dict) VALUES(%s, %s)",[key, Json(value)])
                cur.close()
            conn.close()
        return True

    async def drop_tanner(self, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DROP TABLE tanner")
                cur.close()
            conn.close()
        return True

    async def smembers(self, key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.curssor() as cur:
                data=await cur.execute("SELECT dict FROM tanner WHERE KEY=%s", [key])
                data=await cur.fetchone()
                if data:
                    data=data[0][key]
                else:
                    data=[]
                cur.close()
            conn.close()
        return data
