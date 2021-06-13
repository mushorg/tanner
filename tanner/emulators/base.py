import mimetypes
import re
import urllib.parse
import yarl

from tanner import __version__ as tanner_version
from tanner.config import TannerConfig
from tanner.emulators import (
    lfi,
    rfi,
    sqli,
    xss,
    cmd_exec,
    php_code_injection,
    php_object_injection,
    crlf,
    xxe_injection,
    template_injection,
)  # noqa
from tanner.utils import patterns


class BaseHandler:
    def __init__(self, base_dir, db_name, loop=None):
        self.emulator_enabled = {
            "rfi": TannerConfig.get("EMULATOR_ENABLED", "rfi"),
            "sqli": TannerConfig.get("EMULATOR_ENABLED", "sqli"),
            "lfi": TannerConfig.get("EMULATOR_ENABLED", "lfi"),
            "xss": TannerConfig.get("EMULATOR_ENABLED", "xss"),
            "cmd_exec": TannerConfig.get("EMULATOR_ENABLED", "cmd_exec"),
            "php_code_injection": TannerConfig.get("EMULATOR_ENABLED", "php_code_injection"),
            "php_object_injection": TannerConfig.get("EMULATOR_ENABLED", "php_object_injection"),
            "crlf": TannerConfig.get("EMULATOR_ENABLED", "crlf"),
            "xxe_injection": TannerConfig.get("EMULATOR_ENABLED", "xxe_injection"),
            "template_injection": TannerConfig.get("EMULATOR_ENABLED", "template_injection"),
        }

        self.emulators = {
            "rfi": rfi.RfiEmulator(base_dir, loop=loop, allow_insecure=TannerConfig.get("RFI", "allow_insecure"))
            if self.emulator_enabled["rfi"]
            else None,
            "lfi": lfi.LfiEmulator() if self.emulator_enabled["lfi"] else None,
            "xss": xss.XssEmulator() if self.emulator_enabled["xss"] else None,
            "sqli": sqli.SqliEmulator(db_name, base_dir) if self.emulator_enabled["sqli"] else None,
            "cmd_exec": cmd_exec.CmdExecEmulator() if self.emulator_enabled["cmd_exec"] else None,
            "php_code_injection": php_code_injection.PHPCodeInjection(loop)
            if self.emulator_enabled["php_code_injection"]
            else None,
            "php_object_injection": php_object_injection.PHPObjectInjection(loop)
            if self.emulator_enabled["php_object_injection"]
            else None,
            "crlf": crlf.CRLFEmulator() if self.emulator_enabled["crlf"] else None,
            "xxe_injection": xxe_injection.XXEInjection(loop) if self.emulator_enabled["xxe_injection"] else None,
            "template_injection": template_injection.TemplateInjection(loop)
            if self.emulator_enabled["template_injection"]
            else None,
        }

        self.get_emulators = [
            "sqli",
            "rfi",
            "lfi",
            "xss",
            "php_code_injection",
            "php_object_injection",
            "cmd_exec",
            "crlf",
            "xxe_injection",
            "template_injection",
        ]
        self.post_emulators = [
            "sqli",
            "rfi",
            "lfi",
            "xss",
            "php_code_injection",
            "php_object_injection",
            "cmd_exec",
            "crlf",
            "xxe_injection",
            "template_injection",
        ]
        self.cookie_emulators = ["sqli", "php_object_injection"]

    def extract_get_data(self, path):
        """
        Return all the GET parameter
        :param path (str): The URL path from which GET parameters are to be extracted
        :return: A MultiDictProxy object containg name and value of parameters
        """
        path = urllib.parse.unquote(path)
        encodings = [("&&", "%26%26"), (";", "%3B")]
        for value, encoded_value in encodings:
            path = path.replace(value, encoded_value)
        get_data = yarl.URL(path).query
        return get_data

    async def get_emulation_result(self, session, data, target_emulators):
        """
        Return emulation result for the vulnerabilty of highest order
        :param session (Session object): Current active session
        :param data (MultiDictProxy object): Data to be checked
        :param target_emulator (list): Emulators against which data is to be checked
        :return: A dict object containing name, order and paylod to be injected for vulnerability
        """
        detection = dict(name="unknown", order=0)
        attack_params = {}
        for param_id, param_value in data.items():
            for emulator in target_emulators:
                if TannerConfig.get("EMULATOR_ENABLED", emulator):
                    possible_detection = self.emulators[emulator].scan(param_value) if param_value else None
                    if possible_detection:
                        if detection["order"] < possible_detection["order"]:
                            detection = possible_detection
                        if emulator not in attack_params:
                            attack_params[emulator] = []
                        attack_params[emulator].append(dict(id=param_id, value=param_value))

        if detection["name"] in self.emulators:
            emulation_result = await self.emulators[detection["name"]].handle(attack_params[detection["name"]], session)
            if emulation_result:
                detection["payload"] = emulation_result

        return detection

    async def handle_post(self, session, data):
        post_data = data["post_data"]

        detection = await self.get_emulation_result(session, post_data, self.post_emulators)
        return detection

    async def handle_cookies(self, session, data):
        cookies = data["cookies"]

        detection = await self.get_emulation_result(session, cookies, self.cookie_emulators)
        return detection

    async def handle_get(self, session, data):
        path = data["path"]
        get_data = self.extract_get_data(path)
        detection = dict(name="unknown", order=0)
        # dummy for wp-content
        if re.match(patterns.WORD_PRESS_CONTENT, path):
            detection = {"name": "wp-content", "order": 1}
        elif re.match(patterns.INDEX, path):
            detection = {"name": "index", "order": 1}
        # check attacks against get parameters
        possible_get_detection = await self.get_emulation_result(session, get_data, self.get_emulators)
        if possible_get_detection and detection["order"] < possible_get_detection["order"]:
            detection = possible_get_detection
        # check attacks against cookie values
        possible_cookie_detection = await self.handle_cookies(session, data)
        if possible_cookie_detection and detection["order"] < possible_cookie_detection["order"]:
            detection = possible_cookie_detection

        return detection

    @staticmethod
    def set_injectable_page(session):
        injectable_page = None
        if session:
            for page in reversed(session.paths):
                if mimetypes.guess_type(page["path"])[0] == "text/html":
                    injectable_page = page["path"]

        return injectable_page

    async def emulate(self, data, session):
        if data["method"] == "POST":
            detection = await self.handle_post(session, data)
        else:
            detection = await self.handle_get(session, data)

        if "payload" not in detection:
            detection["type"] = 1
        elif "payload" in detection:
            if "status_code" not in detection["payload"]:
                detection["type"] = 2
                if detection["payload"]["page"]:
                    injectable_page = self.set_injectable_page(session)
                    if injectable_page is None:
                        injectable_page = "/index.html"
                    detection["payload"]["page"] = injectable_page
            else:
                detection["type"] = 3
        detection["version"] = tanner_version
        return detection

    async def handle(self, data, session):
        detection = await self.emulate(data, session)
        return detection
