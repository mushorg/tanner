import asyncio
import json
import logging
import socket
from geoip2.database import Reader
import geoip2
import asyncio_redis
from tanner.dorks_manager import DorksManager


class SessionAnalyzer:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self._loop)
        self.logger = logging.getLogger('tanner.session_analyzer.SessionAnalyzer')

    async def analyze(self, session_key, redis_client):
        session = None
        await asyncio.sleep(1, loop=self._loop)
        try:
            session = await redis_client.get(session_key)
            session = json.loads(session)
        except (asyncio_redis.NotConnectedError, TypeError, ValueError) as error:
            self.logger.error('Can\'t get session for analyze: %s', error)
        else:
            result = await self.create_stats(session, redis_client)
            await self.queue.put(result)
            await self.save_session(redis_client)

    async def save_session(self, redis_client):
        while not self.queue.empty():
            session = await self.queue.get()
            s_key = session['snare_uuid']
            del_key = session['sess_uuid']
            try:
                await redis_client.lpush(s_key, [json.dumps(session)])
                await redis_client.delete([del_key])
            except asyncio_redis.NotConnectedError as redis_error:
                self.logger.error('Error with redis. Session will be returned to the queue: %s',
                                  redis_error)
                self.queue.put(session)

    async def create_stats(self, session, redis_client):
        sess_duration = session['end_time'] - session['start_time']
        rps = session['count'] / sess_duration
        location_info = await self._loop.run_in_executor(
            None, self.find_location, session['peer']['ip']
        )
        tbr, errors, hidden_links, attack_types = await self.analyze_paths(session['paths'],
                                                                           redis_client)

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
            paths=session['paths'],
            cookies=session['cookies']
        )

        owner = await self.choose_possible_owner(stats)
        stats.update(owner)
        return stats

    @staticmethod
    async def analyze_paths(paths, redis_client):
        tbr = []
        attack_types = []
        current_path = paths[0]
        dorks = await redis_client.smembers_asset(DorksManager.dorks_key)

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

    async def choose_possible_owner(self, stats):
        possible_owners = dict(
            user=0.0,
            tool=0.0,
            crawler=0.0,
            attacker=0.0
        )
        attacks = {'rfi', 'sqli', 'lfi', 'xss'}
        bots_owner = ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                      'Googlebot/2.1 (+http://www.google.com/bot.html)',
                      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                      'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 '
                      '(KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; '
                      'bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                      'Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; '
                      'IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; bingbot/2.0; '
                      '+http://www.bing.com/bingbot.htm)']
        possible_owners['crawler'], possible_owners['tool'] = await self.detect_crawler(stats, bots_owner)
        possible_owners['attacker'] = await self.detect_attacker(stats, bots_owner, attacks)

        maxcf = max([possible_owners['crawler'], possible_owners['attacker'], possible_owners['tool']])

        possible_owners['user'] = round(1 - maxcf, 2)

        owners = {k: v for k, v in possible_owners.items() if v != 0}
        return {'possible_owners': owners}

    @staticmethod
    def find_location(ip):
        reader = Reader('./tanner/data/GeoLite2-City.mmdb')
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

    async def detect_crawler(self, stats, bots_owner):
        for _, path in enumerate(stats['paths']):
            if path['path'] == '/robots.txt':
                return (1.0, 0.0)
        if stats['requests_in_second'] > 10:
            if stats['user_agent'] in bots_owner:
                return (0.85, 0.15)
            return (0.5, 0.85)
        if stats['user_agent'] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(
                None, socket.gethostbyaddr, stats['peer_ip']
            )
            if 'search.msn.com' or 'googlebot.com' in hostname:
                return (0.75, 0.15)
            return (0.25, 0.15)
        return (0.0, 0.0)

    async def detect_attacker(self, stats, bots_owner, attacks):
        if set(stats['attack_types']).intersection(attacks):
            return 1.0
        if stats['requests_in_second'] > 10:
            return 0.0
        if stats['user_agent'] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(
                None, socket.gethostbyaddr, stats['peer_ip']
            )
            if 'search.msn.com' or 'googlebot.com' in hostname:
                return 0.25
            return 0.75
        if stats['hidden_links'] > 0:
            return 0.5
        return 0.0
