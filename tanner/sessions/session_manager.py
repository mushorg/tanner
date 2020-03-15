import logging
import hashlib
import asyncio
import aiopg
import time
from psycopg2.extras import Json
import aioredis

from tanner.sessions.session import Session
from tanner.sessions.session_analyzer import SessionAnalyzer


class SessionManager:
    def __init__(self, loop=None):
        self.sessions = {}
        self.analyzer = SessionAnalyzer(loop=loop)
        self.logger = logging.getLogger(__name__)

    async def add_or_update_postgres_session(self, raw_data, postgres_client):
        with postgres_client.acquire() as conn:
            with conn.cursor() as cur:
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

    async def add_or_update_session(self, raw_data, db_client, database):
        # handle raw data
        valid_data = self.validate_data(raw_data)
        # push snare uuid into postgres database.
        if database=='postgres':
            print('in postgress')
            with postgres_client.acquire() as conn:
                with conn.cursor() as cur:
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

        #pushing data into reddis
        else:
            print('in reddis')
            await redis_client.sadd('snare_ids', *[valid_data['uuid']])
        session_id = self.get_session_id(valid_data)
        if session_id not in self.sessions:
            try:
                new_session = Session(valid_data)
            except KeyError as key_error:
                self.logger.exception('Error during session creation: %s', key_error)
                return
            self.sessions[session_id] = new_session
            return new_session, session_id
        else:
            self.sessions[session_id].update_session(valid_data)
        # prepare the list of sessions
        return self.sessions[session_id], session_id

    @staticmethod
    def validate_data(data):
        if 'peer' not in data:
            peer = dict(ip=None, port=None)
            data['peer'] = peer

        data['headers'] = dict((k.lower(), v) for k, v in data['headers'].items())
        if 'user-agent' not in data['headers']:
            data['headers']['user-agent'] = None
        if 'path' not in data:
            data['path'] = None
        if 'uuid' not in data:
            data['uuid'] = None
        if 'status' not in data:
            data['status'] = 200 if 'error' not in data else 500
        if 'cookies' not in data:
            data['cookies'] = dict(sess_uuid=None)
        if 'cookies' in data and 'sess_uuid' not in data['cookies']:
            data['cookies']['sess_uuid'] = None

        return data

    def get_session_id(self, data):
        ip = data['peer']['ip']
        user_agent = data['headers']['user-agent']
        sess_uuid = data['cookies']['sess_uuid']

        sess_id_string = "{ip}{user_agent}{sess_uuid}".format(ip=ip, user_agent=user_agent, sess_uuid=sess_uuid)

        return hashlib.md5(sess_id_string.encode()).hexdigest()

    async def delete_old_sessions(self, redis_client):
        print('in delete_old_sessions')
        id_for_deletion = []
        for sess_id, session in self.sessions.items():
            if not session.is_expired():
                continue
            print(session.get_uuid(), session.to_json())
            is_deleted = await self.delete_session(session, redis_client)
            if is_deleted:
                id_for_deletion.append(sess_id)

        for sess_id in id_for_deletion:
            try:
                del self.sessions[sess_id]
            except ValueError:
                continue

    async def delete_sessions_on_shutdown(self, redis_client):
        print('in delete_sessions_on_shutdown')
        print(self.sessions)
        for sess_id, sess in self.sessions.items():
            print('deleating...')
            print(sess.get_uuid(), sess.to_json())
            is_deleted = await self.delete_session(sess, redis_client)
            if is_deleted:
                del self.sessions[sess_id]

    async def delete_session(self, sess, redis_client):
        print('in delete_session')
        await sess.remove_associated_db()
        if sess.associated_env is not None:
            await sess.remove_associated_env()
        try:
            print(sess.get_uuid(), sess.to_json())
            await redis_client.set(sess.get_uuid(), sess.to_json())
            await self.analyzer.analyze(sess.get_uuid(), redis_client)
        except aioredis.ProtocolError as redis_error:
            self.logger.exception('Error connect to redis, session stay in memory. %s', redis_error)
            print('Error connect to redis, session stay in memory. %s', redis_error)
            return False
        else:
            return True
