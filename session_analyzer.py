import redis
import json
import asyncio
import socket
import operator
from dorks_manager import DorksManager


class SessionAnalyzer:
    def __init__(self):
        self.r = redis.StrictRedis(host='localhost', port=6379)
        self.queue = asyncio.Queue()

    @asyncio.coroutine
    def analyze(self, session_key):
        session = None
        yield from asyncio.sleep(1)
        try:
            session = self.r.get(session_key)
            session = json.loads(session.decode('utf-8'))
        except (redis.ConnectionError, TypeError, ValueError) as e:
            print("Can't get session for analyze", e)
        else:
            result = self.create_stats(session)
            yield from self.queue.put(result)
            yield from self.save_session()

    @asyncio.coroutine
    def save_session(self):
        while not self.queue.empty():
            session = yield from self.queue.get()
            s_key = session['sensor_uuid']
            del_key = session['uuid']
            try:
                self.r.lpush(s_key, json.dumps(session))
                self.r.delete(del_key)
            except redis.ConnectionError as e:
                print('Error with redis. Session will be returned to the queue', e)
                self.queue.put(session)

    def create_stats(self, session):
        sess_duration = session['end_time'] - session['start_time']
        rps = sess_duration / session['count']
        tbr, errors, hidden_links, attack_types = self.analyze_paths(session['paths'])

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

    def analyze_paths(self, paths):
        tbr = []
        attack_types = []
        current_path = paths[0]
        dorks = self.r.smembers(DorksManager.dorks_key)

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

    def choose_possible_owner(self, stats):
        possible_owners = dict(
            user=0,
            tool=0,
            crawler=0,
            attacker=0
        )
        attacks = {'rfi', 'sqli', 'lfi', 'xss'}
        bots_owner = ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
                      'Googlebot/2.1 (+http://www.google.com/bot.html)'
                      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
                      'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
                      'Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)']
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
