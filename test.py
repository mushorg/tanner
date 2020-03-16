import aiopg
import asyncio
from psycopg2.extras import Json
class Test:
    async def test_from_diff_method(pool, valid_data, koi):
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                required_dict=dict(snare_ids_new_4=[valid_data['uuid']])
                await cur.execute('INSERT INTO test_tanner(key,dict) VALUES(%s,%s)', [koi,Json(required_dict)])
                cur.close()
            conn.close()
        return True
async def go(dsn):
    pool = await aiopg.create_pool(dsn, maxsize=80)
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            valid_data={'method': 'GET', 'path': '/', 'headers': {'Host': '127.0.0.1:8080', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive', 'Cookie': '_ga=GA1.1.948770098.1583266448; sess_uuid=fe65efaf-8fed-420f-87a5-50aab68822f8', 'Upgrade-Insecure-Requests': '1', 'Cache-Control': 'max-age=0'}, 'uuid': 'fe65efaf-8fed-420f-87a5-50aab68822f8', 'peer': {'ip': '127.0.0.1', 'port': 34446}, 'status': 200, 'cookies': {'_ga': 'GA1.1.948770098.1583266448', ' sess_uuid': 'fe65efaf-8fed-420f-87a5-50aab68822f8'}}
            await cur.execute('CREATE TABLE IF NOT EXISTS test_tanner(key text, dict JSONB)')
            await cur.execute('SELECT key FROM test_tanner')
            keys_get=await cur.fetchall()
            keys=[]
            for temp in keys_get:
                keys.append(temp[0])
            koi='snare_ids_new_4'
            print(keys)
            if keys:
                if koi in keys:
                    print('accessing previous daata')
                    await cur.execute("SELECT dict FROM test_tanner WHERE key=%s",[koi])
                    print(cur.query)
                    row=await cur.fetchone()
                    print(row)
                    previous_data=row[0]['{}'.format(koi)]
                    required_dict=dict(snare_ids_new_4=previous_data)
                    required_dict[koi].append(valid_data['uuid'])
                    await cur.execute("UPDATE test_tanner SET dict=%s WHERE key=%s", [Json(required_dict),koi])
                else:
                    print('creating new data')
                    created=await Test.test_from_diff_method(pool, valid_data, koi)
            else:
                print('creating first commit')
                required_dict=dict(snare_ids_new=[valid_data['uuid']])
                await cur.execute('INSERT INTO test_tanner(key,dict) VALUES(%s,%s)', [koi,Json(required_dict)])

#            print(row, type(row), row[0])
            print('Done')
            cur.close()
        conn.close()


if __name__=='__main__':
    dsn='dbname=tanner user=postgres password=mark@2187 host=localhost port=5432'
    loop = asyncio.new_event_loop()
    loop.run_until_complete(go(dsn))
