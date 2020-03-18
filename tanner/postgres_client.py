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
                    await cur.execute("CREATE TABLE IF NOT EXISTS tanner_snare(sess_id SERIAL PRIMARY KEY, key text, score float, dict JSONB)")
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
    async def delete_tanner(key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.curssor() as cur:
                await cur.execute("DELETE FROM tanner WHERE key=%s",[key])
                cur.close()
            conn.close()
        return True

    async def delete_snare_id(key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.curssor() as cur:
                await cur.execute("DELETE FROM tanner_snare WHERE key=%s",[key])
                cur.close()
            conn.close()
        return True

    async def update_postgres_session(key, new_data, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                updated_data={'{}'.format(key):[new_data]}
                await cur.execute("UPDATE tanner SET dict=%s WHERE key=%s", [Json(updated_data), key])
                cur.close()
            conn.close()
        return True

    async def get(self, key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT dict FROM tanner WHERE key=%s",[key])
                data = await cur.fetchall()
                data=data[0][key]
                cur.close()
            conn.close()
        return data

    async def get_tanner_snare(self, key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT dict FROM tanner_snare WHERE key=%s",[key])
                data = await cur.fetchall()
                data=data[0][key]
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

    async def set_tanner_snare(self, key, value, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("INSERT INTO tanner_snare(key, dict) VALUES(%s, %s)",[key, Json(value)])
                cur.close()
            conn.close()
        return True

    async def drop_tanner(self, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DROP TABLE tanner")
                await cur.execute("DROP TABLE tanner_session")
                cur.close()
            conn.close()
        return True

    async def smembers(self, key, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.curssor() as cur:
                data=await cur.execute("SELECT dict FROM tanner WHERE KEY=%s", [key])
                data=await cur.fetchall()
                if data:
                    data=data[0][key]
                else:
                    data=[]
                cur.close()
            conn.close()
        return data

    async def zadd(self, key, score, value, postgres_client):
        async with postgres_client.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("INSERT INTO tanner_snare(key, score, dict) VALUES(%s, %f, %s)",[key, dict, score])
                cur.close()
            conn.close()
        return True
