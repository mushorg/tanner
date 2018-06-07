import asyncio
import json
from urllib.request import urlopen
import logging
import operator
import socket

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
        rps = sess_duration / session['count']
        location_info = self.find_location(session['peer']['ip'])
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

        owner = self.choose_possible_owner(stats)
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

    @staticmethod
    def choose_possible_owner(stats):
        possible_owners = dict(
            user=0,
            tool=0,
            crawler=0,
            attacker=0
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
        if stats['user_agent'] in bots_owner:
            hostname, _, _ = socket.gethostbyaddr(stats['peer_ip'])
            if 'search.msn.com' or 'googlebot.com' in hostname:
                possible_owners['crawler'] += 1
            else:
                possible_owners['attacker'] += 1
        if stats['requests_in_second'] >= 10:
            possible_owners['tool'] += 1
            possible_owners['crawler'] += 1
        else:
            possible_owners['user'] += 1
            possible_owners['attacker'] += 1
        if stats['hidden_links'] > 0:
            possible_owners['crawler'] += 1
            possible_owners['attacker'] += 1
        if set(stats['attack_types']).intersection(attacks):
            possible_owners['attacker'] += 1

        maxval = max(possible_owners.items(), key=operator.itemgetter(1))[1]
        owners = [k for k, v in possible_owners.items() if v == maxval]
        return {'possible_owners': owners}
    
    @staticmethod
    def find_location(ip):
        url = "http://www.freegeoip.net/json/{0}".format(ip)
        location_info = json.loads(urlopen(url).read())
        info = dict(
            country=location_info['country_name'],
            country_code=location_info['country_code'],
            region=location_info['region_name'],
            region_code=location_info['region_code'],
            city=location_info['city'],
            zip_code=location_info['zip_code'],
            time_zone=location_info['time_zone']
        )          
        return dict(info)
