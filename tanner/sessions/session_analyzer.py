import asyncio
import json
import logging
import socket
from geoip2.database import Reader
import geoip2
import aioredis
from tanner.dorks_manager import DorksManager
from tanner.config import TannerConfig


class SessionAnalyzer:
    def __init__(self, loop=None):
        self._loop = loop if loop is not None else asyncio.get_event_loop()
        self.queue = asyncio.Queue()
        self.logger = logging.getLogger("tanner.session_analyzer.SessionAnalyzer")
        self.attacks = ["sqli", "rfi", "lfi", "xss", "php_code_injection", "cmd_exec", "crlf"]

    async def analyze(self, session_key, redis_client):
        session = None
        await asyncio.sleep(1)
        try:
            session = await redis_client.get(session_key, encoding="utf-8")
            session = json.loads(session)
        except (aioredis.ConnectionError, TypeError, ValueError) as error:
            self.logger.exception("Can't get session for analyze: %s", error)
        else:
            result = await self.create_stats(session, redis_client)
            await self.queue.put(result)
            await self.save_session(redis_client)

    async def save_session(self, redis_client):
        while not self.queue.empty():
            session = await self.queue.get()
            s_key = session["snare_uuid"]
            del_key = session["sess_uuid"]
            try:
                await redis_client.zadd(s_key, session["start_time"], json.dumps(session))
                await redis_client.delete(*[del_key])
            except aioredis.ConnectionError as redis_error:
                self.logger.exception("Error with redis. Session will be returned to the queue: %s", redis_error)
                self.queue.put(session)

    async def create_stats(self, session, redis_client):
        sess_duration = session["end_time"] - session["start_time"]
        referer = None
        if sess_duration != 0:
            rps = session["count"] / sess_duration
        else:
            rps = 0
        location_info = await self._loop.run_in_executor(None, self.find_location, session["peer"]["ip"])
        tbr, errors, hidden_links, attack_types = await self.analyze_paths(session["paths"], redis_client)
        attack_count = self.set_attack_count(attack_types)

        stats = dict(
            sess_uuid=session["sess_uuid"],
            peer_ip=session["peer"]["ip"],
            peer_port=session["peer"]["port"],
            location=location_info,
            user_agent=session["user_agent"],
            snare_uuid=session["snare_uuid"],
            start_time=session["start_time"],
            end_time=session["end_time"],
            requests_in_second=rps,
            approx_time_between_requests=tbr,
            accepted_paths=session["count"],
            errors=errors,
            hidden_links=hidden_links,
            attack_types=attack_types,
            attack_count=attack_count,
            paths=session["paths"],
            cookies=session["cookies"],
            referer=session["referer"],
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
            tbr.append(path["timestamp"] - current_path["timestamp"])
            current_path = path
        tbr_average = sum(tbr) / float(len(tbr))

        errors = 0
        hidden_links = 0
        for path in paths:
            if path["response_status"] != 200:
                errors += 1
            if path["path"] in dorks:
                hidden_links += 1
            if "attack_type" in path:
                attack_types.append(path["attack_type"])
        return tbr_average, errors, hidden_links, attack_types

    def set_attack_count(self, attack_types):
        attacks = self.attacks.copy()
        attacks.append("index")
        attack_count = {k: 0 for k in attacks}
        for attack in attacks:
            attack_count[attack] = attack_types.count(attack)
        count = {k: v for k, v in attack_count.items() if v != 0}
        return count

    async def choose_possible_owner(self, stats):
        owner_names = ["user", "tool", "crawler", "attacker", "admin"]
        possible_owners = {k: 0.0 for k in owner_names}
        if stats["peer_ip"] == "127.0.0.1" or stats["peer_ip"] == "::1":
            possible_owners["admin"] = 1.0
        with open(TannerConfig.get("DATA", "crawler_stats")) as f:
            bots_owner = await self._loop.run_in_executor(None, f.read)
        crawler_hosts = ["googlebot.com", "baiduspider", "search.msn.com", "spider.yandex.com", "crawl.sogou.com"]
        possible_owners["crawler"], possible_owners["tool"] = await self.detect_crawler(
            stats, bots_owner, crawler_hosts
        )
        possible_owners["attacker"] = await self.detect_attacker(stats, bots_owner, crawler_hosts)
        maxcf = max([possible_owners["crawler"], possible_owners["attacker"], possible_owners["tool"]])

        possible_owners["user"] = round(1 - maxcf, 2)

        owners = {k: v for k, v in possible_owners.items() if v != 0}
        return {"possible_owners": owners}

    @staticmethod
    def find_location(ip):
        reader = Reader(TannerConfig.get("DATA", "geo_db"))
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
        for path in stats["paths"]:
            if path["path"] == "/robots.txt":
                return (1.0, 0.0)
        if stats["requests_in_second"] > 10:
            if stats["referer"] is not None:
                return (0.0, 0.5)
            if stats["user_agent"] is not None and stats["user_agent"] in bots_owner:
                return (0.85, 0.15)
            return (0.5, 0.85)
        if stats["user_agent"] is not None and stats["user_agent"] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(None, socket.gethostbyaddr, stats["peer_ip"])
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return (0.75, 0.15)
            return (0.25, 0.15)
        return (0.0, 0.0)

    async def detect_attacker(self, stats, bots_owner, crawler_hosts):
        if set(stats["attack_types"]).intersection(self.attacks):
            return 1.0
        if stats["requests_in_second"] > 10:
            return 0.0
        if stats["user_agent"] is not None and stats["user_agent"] in bots_owner:
            hostname, _, _ = await self._loop.run_in_executor(None, socket.gethostbyaddr, stats["peer_ip"])
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return 0.25
            return 0.75
        if stats["hidden_links"] > 0:
            return 0.5
        return 0.0
