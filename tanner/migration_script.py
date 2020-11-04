import asyncio
import json
import psycopg2
import aioredis
from tanner import redis_client, postgres_client, dbutils


async def check_session_data(result):
    """Make sure that the data we received doesn't
       have any Null values assigned to it.

    Args:
        result (dict): The session data we got from redis
    """
    Integers = [
        "zip_code",
        "errors",
        "accepted_paths",
        "port",
        "approx_time_between_requests",
        "requests_in_second",
        "hidden_links",
    ]

    if result["location"] == "NA":
        result["location"] = dict(
            country=None,
            country_code=None,
            city=None,
            zip_code="NA",
        )

    for key, value in result.items():
        if not value:
            if key in Integers:
                result[key] = 0
            else:
                result[key] = "N/A"


async def main():
    r_client = await redis_client.RedisClient.get_redis_client()
    pg_client = await postgres_client.PostgresClient().get_pg_client()
    await dbutils.DBUtils.create_data_tables(pg_client)

    try:
        print("[INFO] Reading from Redis")
        keys = await r_client.keys("[0-9a-f]*")
    except (aioredis.ProtocolError, TypeError, ValueError) as error:
        print("Can't get session for analyze: %s", error)
    else:
        print("[INFO] Moving to Postgres")

        for key in keys:
            try:
                sessions = await r_client.zrevrangebyscore(key, encoding="utf-8")
                sessions = json.loads(sessions[0])
                for sess in sessions:
                    result = json.loads(sess)
                    await check_session_data(result)

                    try:
                        await dbutils.DBUtils.add_analyzed_data(result, pg_client)
                        await r_client.delete(*[key])
                    except psycopg2.ProgrammingError as pg_error:
                        print(
                            "Error with Postgres: %s. Session with session-id %s will not be added to postgres",
                            pg_error,
                            key,
                        )
                    except aioredis.ProtocolError as redis_error:
                        print(
                            "Error with redis: %s. Session with session-id %s will not be removed from redis.",
                            redis_error,
                            key,
                        )
            except aioredis.errors.ReplyError:
                continue

    r_client.close()
    await r_client.wait_closed()
    pg_client.close()
    await pg_client.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
