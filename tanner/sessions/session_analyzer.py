import asyncio
import json
import logging
import socket
import psycopg2
from datetime import datetime
from geoip2.database import Reader
import geoip2
import aioredis
from tanner.dorks_manager import DorksManager
from tanner.config import TannerConfig
from tanner.dbutils import DBUtils


class SessionAnalyzer:
    def __init__(self, loop=None):
        self.logger = logging.getLogger("tanner.session_analyzer.SessionAnalyzer")
        self.attacks = [
            "sqli",
            "rfi",
            "lfi",
            "xss",
            "php_code_injection",
            "cmd_exec",
            "crlf",
        ]

    async def analyze(self, redis_client, pg_client):
        """Perform analysis on the sessions, store the analyzed
        session in postgres and then delete that session from redis.
        """
        _loop = asyncio.get_running_loop()
        sessions = None
        await asyncio.sleep(1, loop=_loop)

        try:
            keys = await redis_client.keys("[0-9a-f]*")
        except (aioredis.ProtocolError, TypeError, ValueError) as error:
            self.logger.exception("Can't get session for analyze: %s", error)
        else:
            for key in keys:
                try:
                    session = await redis_client.get(key, encoding="utf-8")
                    session = json.loads(session)

                    result = await self.create_stats(session, redis_client)

                    del_key = result["sess_uuid"]
                    try:
                        await DBUtils.add_analyzed_data(result, pg_client)
                        await redis_client.delete(*[del_key])
                    except psycopg2.ProgrammingError as pg_error:
                        self.logger.exception(
                            "Error with Postgres: %s. Session with session-id %s will not be added to postgres",
                            pg_error,
                            key,
                        )
                    except aioredis.ProtocolError as redis_error:
                        self.logger.exception(
                            "Error with redis: %s. Session with session-id %s will not be removed from redis.",
                            redis_error,
                            key,
                        )
                # This is the key which stores all the dorks.
                # It matches the pattern of other keys.
                except aioredis.errors.ReplyError:
                    continue

    async def create_stats(self, session, redis_client):
        sess_duration = session["end_time"] - session["start_time"]
        referer = None
        if sess_duration != 0:
            rps = session["count"] / sess_duration
        else:
            rps = 0
        _loop = asyncio.get_running_loop()
        location_info = await _loop.run_in_executor(
            None, self.find_location, session["peer"]["ip"]
        )
        tbr, errors, hidden_links, attack_types = await self.analyze_paths(
            session["paths"], redis_client
        )
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
        _loop = asyncio.get_running_loop()
        with open(TannerConfig.get("DATA", "crawler_stats")) as f:
            bots_owner = await _loop.run_in_executor(None, f.read)
        crawler_hosts = [
            "googlebot.com",
            "baiduspider",
            "search.msn.com",
            "spider.yandex.com",
            "crawl.sogou.com",
        ]
        possible_owners["crawler"], possible_owners["tool"] = await self.detect_crawler(
            stats, bots_owner, crawler_hosts
        )
        possible_owners["attacker"] = await self.detect_attacker(
            stats, bots_owner, crawler_hosts
        )
        maxcf = max(
            [
                possible_owners["crawler"],
                possible_owners["attacker"],
                possible_owners["tool"],
            ]
        )

        possible_owners["user"] = round(1 - maxcf, 2)

        owners = {k: v for k, v in possible_owners.items() if v != 0}
        return {"possible_owners": owners}

    @staticmethod
    def find_location(ip):
        reader = Reader(TannerConfig.get("DATA", "geo_db"))
        try:
            location = reader.city(ip)
            if location.postal.code is None:
                zcode = "NA"
            else:
                zcode = str(location.postal.code)

            info = dict(
                country=location.country.name,
                country_code=location.country.iso_code,
                city=location.city.name,
                zip_code=zcode,
            )
        except geoip2.errors.AddressNotFoundError:
            # When IP doesn't exist in the db, set info as "NA - Not Available"
            info = dict(
                country=None,
                country_code=None,
                city=None,
                zip_code="NA",
            )
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
        _loop = asyncio.get_running_loop()
        if stats["user_agent"] is not None and stats["user_agent"] in bots_owner:
            hostname, _, _ = await _loop.run_in_executor(
                None, socket.gethostbyaddr, stats["peer_ip"]
            )
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return (0.75, 0.15)
            return (0.25, 0.15)
        return (0.0, 0.0)

    async def detect_attacker(self, stats, bots_owner, crawler_hosts):
        _loop = asyncio.get_running_loop()
        if set(stats["attack_types"]).intersection(self.attacks):
            return 1.0
        if stats["requests_in_second"] > 10:
            return 0.0
        if stats["user_agent"] is not None and stats["user_agent"] in bots_owner:
            hostname, _, _ = await _loop.run_in_executor(
                None, socket.gethostbyaddr, stats["peer_ip"]
            )
            if hostname is not None:
                for crawler_host in crawler_hosts:
                    if crawler_host in hostname:
                        return 0.25
            return 0.75
        if stats["hidden_links"] > 0:
            return 0.5
        return 0.0
