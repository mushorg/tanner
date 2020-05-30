import asyncio
import json
import logging
import socket
from datetime import datetime
from geoip2.database import Reader
import geoip2
import aioredis
from tanner.dorks_manager import DorksManager
from tanner.config import TannerConfig
from tanner.utils.attack_type import AttackType

# TODO: Move Query from here
COOKIE_INSERT_QUERY = "INSERT INTO cookies(session_id, key, value) VALUES('{uuid}', '{key}', '{value}');"


class SessionAnalyzer:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self._loop)
        self.logger = logging.getLogger('tanner.session_analyzer.SessionAnalyzer')
        self.attacks = ['sqli', 'rfi', 'lfi', 'xss', 'php_code_injection', 'cmd_exec', 'crlf']

    async def analyze(self, session_key, redis_client, pg_client):
        session = None
        await asyncio.sleep(1, loop=self._loop)
        try:
            session = await redis_client.get(session_key, encoding='utf-8')
            session = json.loads(session)
        except (aioredis.ProtocolError, TypeError, ValueError) as error:
            self.logger.exception('Can\'t get session for analyze: %s', error)
        else:
            result = await self.create_stats(session, redis_client)
            await self.queue.put(result)
            await self.save_session(redis_client, pg_client)

    async def save_session(self, redis_client, pg_client):
        while not self.queue.empty():
            columns = (
                'id, sensor_id, ip, port, {}, user_agent, start_time, '
                'end_time, rps, atbr, accepted_paths, errors, hidden_links, referer'
            )

            session = await self.queue.get()
            s_key = session["snare_uuid"]
            del_key = session["sess_uuid"]
            print("Printing sessions")

            start_time = datetime.fromtimestamp(session["start_time"]).strftime('%Y-%m-%d %H:%M:%S')
            end_time = datetime.fromtimestamp(session["end_time"]).strftime('%Y-%m-%d %H:%M:%S')

            # Some of the sessions have location as NA
            try:
                country_info = True
                country = session["location"]["country"]
                country_code = session["location"]["country_code"]
                city = session["location"]["city"]
                zip_code = session["location"]["zip_code"]
            except (TypeError, KeyError):
                country_info = False
                location = session["location"]

            try:
                # TODO: pg_client to insert
                if country_info:
                    all_columns = columns.format(
                        "country, country_code, city, zip_code"
                    )

                    sessions_query = (
                        "INSERT INTO sessions ({cols}) "
                        "VALUES ('{uuid}','{sensor}','{ip}',{port},{country},"
                        "{ccode},{city},{zcode},'{ua}','{st}','{et}',{rps},"
                        "{atbr},{apaths},{err},{hlinks},'{referer}');"
                    ).format(
                        cols=all_columns,
                        uuid=session["sess_uuid"],
                        sensor=session["snare_uuid"],
                        ip=session["peer_ip"],
                        port=session["peer_port"],
                        country=country,
                        ccode=country_code,
                        city=city,
                        zcode=zip_code,
                        ua=session["user_agent"],
                        st=start_time,
                        et=end_time,
                        rps=session["requests_in_second"],
                        atbr=session["approx_time_between_requests"],
                        apaths=session["accepted_paths"],
                        err=session["errors"],
                        hlinks=session["hidden_links"],
                        referer=session["referer"]
                    )
                else:
                    all_columns = columns.format("country")
                    sessions_query = (
                        "INSERT INTO sessions ({cols}) "
                        "VALUES ('{uuid}','{sensor}','{ip}',{port},'{country}',"
                        "'{ua}','{st}','{et}',{rps},{atbr},{apaths},{err},{hlinks},"
                        "'{referer}');"
                    ).format(
                        cols=all_columns.strip(),
                        uuid=session["sess_uuid"],
                        sensor=session["snare_uuid"],
                        ip=session["peer_ip"],
                        port=session["peer_port"],
                        country=location,
                        ua=session["user_agent"],
                        st=start_time,
                        et=end_time,
                        rps=session["requests_in_second"],
                        atbr=session["approx_time_between_requests"],
                        apaths=session["accepted_paths"],
                        err=session["errors"],
                        hlinks=session["hidden_links"],
                        referer=session["referer"],
                    )
                    print(sessions_query)

                async with pg_client.acquire() as conn:
                    async with conn.cursor() as cur:
                        await cur.execute(sessions_query)
                        # TODO: Log instead of printing

                        for k, v in session["cookies"].items():
                            await cur.execute(
                                COOKIE_INSERT_QUERY.format(uuid=session["sess_uuid"], key=k, value=v)
                            )
                        for path in session["paths"]:
                            timestamp = datetime.fromtimestamp(path["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
                            paths_query = (
                                "INSERT INTO paths (session_id, path, created_at, response_status, attack_type) "
                                "VALUES ('{id}','{path}','{time}',{res},{atype});"
                            ).format(
                                id=session["sess_uuid"],
                                path=path["path"],
                                time=timestamp,
                                res=path["response_status"],
                                atype=AttackType[path["attack_type"]]
                            )

                            await cur.execute(paths_query)

                        owners_query = (
                            "INSERT INTO owners (session_id, key, value) "
                            "VALUES ('{id}', '{key}', '{val}');"
                        )
                        for k, v in session["possible_owners"].items():
                            await cur.execute(owners_query.format(id=session["sess_uuid"], key=k, val=v))

                    cur.close()
                conn.close()

                await redis_client.delete(*[del_key])
            except aioredis.ProtocolError as redis_error:
                self.logger.exception(
                    "Error with redis. Session will be returned to the queue: %s",
                    redis_error,
                )
                self.queue.put(session)

    async def create_stats(self, session, redis_client):
        sess_duration = session['end_time'] - session['start_time']
        referer = None
        if sess_duration != 0:
            rps = session['count'] / sess_duration
        else:
            rps = 0
        location_info = await self._loop.run_in_executor(
            None, self.find_location, session['peer']['ip']
        )
        tbr, errors, hidden_links, attack_types = await self.analyze_paths(session['paths'],
                                                                           redis_client)
        attack_count = self.set_attack_count(attack_types)

        stats = dict(
            sess_uuid=session['sess_uuid'],
            peer_ip=session['peer']['ip'],
            peer_port=session['peer']['port'],
            location=location_info,
            user_agent=session['user_agent'],
            snare_uuid=session['snare_uuid'],
            start_time=session['start_time'],
            end_time=session['end_time'],
            requests_in_second=rps,
            approx_time_between_requests=tbr,
            accepted_paths=session['count'],
            errors=errors,
            hidden_links=hidden_links,
            attack_types=attack_types,
            attack_count=attack_count,
            paths=session['paths'],
            cookies=session['cookies'],
            referer=session['referer']
        )

        owner = await self.choose_possible_owner(stats)
        stats.update(owner)
        return stats

    @staticmethod
    async def analyze_paths(paths, redis_client):
        tbr = []
        attack_types = []
        current_path = paths[0]
        dorks = await redis_client.smembers(DorksManager.dorks_key)

        for _, path in enumerate(paths, start=1):
            tbr.append(path['timestamp'] - current_path['timestamp'])
            current_path = path
        tbr_average = sum(tbr) / float(len(tbr))

        errors = 0
        hidden_links = 0
        for path in paths:
            if path['response_status'] != 200:
                errors += 1
            if path['path'] in dorks:
                hidden_links += 1
            if 'attack_type' in path:
                attack_types.append(path['attack_type'])
        return tbr_average, errors, hidden_links, attack_types

    def set_attack_count(self, attack_types):
        attacks = self.attacks.copy()
        attacks.append('index')
        attack_count = {k: 0 for k in attacks}
        for attack in attacks:
            attack_count[attack] = attack_types.count(attack)
        count = {k: v for k, v in attack_count.items() if v != 0}
        return count

    async def choose_possible_owner(self, stats):
        owner_names = ['user', 'tool', 'crawler', 'attacker', 'admin']
        possible_owners = {k: 0.0 for k in owner_names}
        if stats['peer_ip'] == '127.0.0.1' or stats['peer_ip'] == '::1':
            possible_owners['admin'] = 1.0
        with open(TannerConfig.get('DATA', 'crawler_stats')) as f:
            bots_owner = await self._loop.run_in_executor(None, f.read)
        crawler_hosts = ['googlebot.com', 'baiduspider', 'search.msn.com', 'spider.yandex.com', 'crawl.sogou.com']
        possible_owners['crawler'], possible_owners['tool'] = await self.detect_crawler(
            stats, bots_owner, crawler_hosts
        )
        possible_owners['attacker'] = await self.detect_attacker(
            stats, bots_owner, crawler_hosts
        )
        maxcf = max([possible_owners['crawler'], possible_owners['attacker'], possible_owners['tool']])

        possible_owners['user'] = round(1 - maxcf, 2)

        owners = {k: v for k, v in possible_owners.items() if v != 0}
        return {'possible_owners': owners}

    @staticmethod
    def find_location(ip):
        reader = Reader(TannerConfig.get('DATA', 'geo_db'))
        try:
            location = reader.city(ip)
            info = dict(
                country=location.country.name,
                country_code=location.country.iso_code,
                city=location.city.name,
                zip_code=location.postal.code,
            )
        except geoip2.errors.AddressNotFoundError:
            info = "NA"  # When IP doesn't exist in the db, set info as "NA - Not Available"
        return info

    async def detect_crawler(self, stats, bots_owner, crawler_hosts):
        for path in stats['paths']:
            if path['path'] == '/robots.txt':
                return (1.0, 0.0)
        if stats['requests_in_second'] > 10:
            if stats['referer'] is not None:
                return (0.0, 0.5)
            if stats['user_agent'] is not None and stats['user_agent'] in bots_owner:
                return (0.85, 0.15)
            return (0.5, 0.85)
        if stats['user_agent'] is not None and stats['user_agent'] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(
                None, socket.gethostbyaddr, stats['peer_ip']
            )
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return (0.75, 0.15)
            return (0.25, 0.15)
        return (0.0, 0.0)

    async def detect_attacker(self, stats, bots_owner, crawler_hosts):
        if set(stats['attack_types']).intersection(self.attacks):
            return 1.0
        if stats['requests_in_second'] > 10:
            return 0.0
        if stats['user_agent'] is not None and stats['user_agent'] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(
                None, socket.gethostbyaddr, stats['peer_ip']
            )
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return 0.25
            return 0.75
        if stats['hidden_links'] > 0:
            return 0.5
        return 0.0
