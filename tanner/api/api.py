import json
import logging
import operator
import aioredis


class Api:
    def __init__(self, redis_client):
        self.logger = logging.getLogger('tanner.api.Api')
        self.redis_client = redis_client

    async def return_snares(self):
        query_res = []
        try:
            query_res = await self.redis_client.smembers('snare_ids', encoding='utf-8')
        except aioredis.ProtocolError as connection_error:
            self.logger.exception('Can not connect to redis %s', connection_error)
        return list(query_res)

    async def return_snare_stats(self, snare_uuid):
        result = {}
        sessions = await self.return_snare_info(snare_uuid)
        if sessions == 'Invalid SNARE UUID':
            return result

        result['total_sessions'] = len(sessions)
        result['total_duration'] = 0
        result['attack_frequency'] = {'sqli': 0,
                                      'lfi': 0,
                                      'xss': 0,
                                      'rfi': 0,
                                      'cmd_exec': 0}

        for sess in sessions:
            result['total_duration'] += sess['end_time'] - sess['start_time']
            for attack in sess['attack_types']:
                if attack in result['attack_frequency']:
                    result['attack_frequency'][attack] += 1

        return result

    async def return_snare_info(self, uuid, count=-1):
        query_res = []
        try:
            query_res = await self.redis_client.zrevrangebyscore(
                uuid, offset=0, count=count, encoding='utf-8'
            )
        except aioredis.ProtocolError as connection_error:
            self.logger.exception('Can not connect to redis %s', connection_error)
        else:
            if not query_res:
                return 'Invalid SNARE UUID'
            for (i, val) in enumerate(query_res):
                query_res[i] = json.loads(val)
        return query_res

    async def return_session_info(self, sess_uuid, snare_uuid=None):
        if snare_uuid:
            snare_uuids = [snare_uuid]
        else:
            snare_uuids = await self.return_snares()

        for snare_id in snare_uuids:
            sessions = await self.return_snare_info(snare_id)
            if sessions == 'Invalid SNARE UUID':
                continue
            for sess in sessions:
                if sess['sess_uuid'] == sess_uuid:
                    return sess

    async def return_sessions(self, filters):
        snare_uuids = await self.return_snares()

        matching_sessions = []
        for snare_id in snare_uuids:
            result = await self.return_snare_info(snare_id)
            if result == 'Invalid SNARE UUID':
                return 'Invalid filter : SNARE UUID'
            sessions = result
            for sess in sessions:
                match_count = 0
                for filter_name, filter_value in filters.items():
                    try:
                        if self.apply_filter(filter_name, filter_value, sess):
                            match_count += 1
                    except KeyError:
                        return 'Invalid filter : %s' % filter_name

                if match_count == len(filters):
                    matching_sessions.append(sess)

        return matching_sessions

    def apply_filter(self, filter_name, filter_value, sess):
        available_filters = {'user_agent': operator.contains,
                             'peer_ip': operator.eq,
                             'attack_types': operator.contains,
                             'possible_owners': operator.contains,
                             'start_time': operator.le,
                             'end_time': operator.ge,
                             'snare_uuid': operator.eq
                             }

        try:
            if available_filters[filter_name] is operator.contains:
                return available_filters[filter_name](sess[filter_name], filter_value)
            else:
                return available_filters[filter_name](filter_value, sess[filter_name])
        except KeyError:
            raise
