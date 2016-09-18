import asyncio
import json
import logging
import operator
import socket

import asyncio_redis

from tanner.dorks_manager import DorksManager


class SessionAnalyzer:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.logger = logging.getLogger('tanner.session_analyzer.SessionAnalyzer')

    @asyncio.coroutine
    def analyze(self, session_key, redis_client):
        session = None
        yield from asyncio.sleep(1)
        try:
            session = yield from redis_client.get(session_key)
            session = json.loads(session)
        except (asyncio_redis.NotConnectedError, TypeError, ValueError) as error:
            self.logger.error('Can\'t get session for analyze: %s', error)
        else:
            result = yield from self.create_stats(session, redis_client)
            yield from self.queue.put(result)
            yield from self.save_session(redis_client)

    @asyncio.coroutine
    def save_session(self, redis_client):
        while not self.queue.empty():
            session = yield from self.queue.get()
            s_key = session['sensor_uuid']
            del_key = session['uuid']
            try:
                yield from redis_client.lpush(s_key, [json.dumps(session)])
                yield from redis_client.delete([del_key])
            except asyncio_redis.NotConnectedError as redis_error:
                self.logger.error('Error with redis. Session will be returned to the queue: %s',
                                  redis_error)
                self.queue.put(session)

    @asyncio.coroutine
    def create_stats(self, session, redis_client):
        sess_duration = session['end_time'] - session['start_time']
        rps = sess_duration / session['count']
        tbr, errors, hidden_links, attack_types = yield from self.analyze_paths(session['paths'],
                                                                                redis_client)

        stats = dict(
            uuid=session['uuid'],
            peer_ip=session['peer']['ip'],
            peer_port=session['peer']['port'],
            user_agent=session['user_agent'],
            sensor_uuid=session['sensor'],
            start_time=session['start_time'],
            end_time=session['end_time'],
            requests_in_second=rps,
            approx_time_between_requests=tbr,
            accepted_paths=session['count'],
            errors=errors,
            hidden_links=hidden_links,
            attack_types=attack_types,
            paths=session['paths']
        )

        owner = self.choose_possible_owner(stats)
        stats.update(owner)
        return stats

    @staticmethod
    @asyncio.coroutine
    def analyze_paths(paths, redis_client):
        tbr = []
        attack_types = []
        current_path = paths[0]
        dorks = yield from redis_client.smembers_asset(DorksManager.dorks_key)

        for i, path in enumerate(paths, start=1):
            tbr.append(path['timestamp'] - current_path['timestamp'])
            current_path = path
        tbr_average = sum(tbr) / float(len(tbr))

        errors = 0
        hidden_links = 0
        for path in paths:
            if path['response_status'] is not 200:
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
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(stats['peer_ip'])
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
