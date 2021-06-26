import configparser
import os
import unittest
import yaml

from unittest import mock
from tanner import config


class TestConfig(unittest.TestCase):
    def setUp(self):
        config.TannerConfig.config = None
        self.d = {
            "DATA": {
                "db_config": "/tmp/user_tanner/db/db_config.json",
                "dorks": "/tmp/user_tanner/data/dorks.pickle",
                "user_dorks": "/tmp/user_tanner/data/user_dorks.pickle",
            },
            "TANNER": {"host": "0.0.0.0", "port": "9000"},
            "WEB": {"host": "0.0.0.0", "port": "9001"},
            "API": {"host": "0.0.0.0", "port": "9002"},
            "PHPOX": {"host": "0.0.0.0", "port": "8088"},
            "REDIS": {"host": "localhost", "port": "6379", "poolsize": "80", "timeout": "5"},
            "EMULATORS": {"root_dir": "/opt/tanner"},
            "EMULATOR_ENABLED": {"sqli": "True", "rfi": "True", "lfi": "True", "xss": "True", "cmd_exec": "True"},
            "SQLI": {
                "type": "SQLITE",
                "db_name": "user_tanner_db",
                "host": "localhost",
                "user": "user_name",
                "password": "user_pass",
            },
            "DOCKER": {"host_image": "test_image"},
            "LOGGER": {"log_debug": "/opt/tanner/tanner.log", "log_err": "/opt/tanner/tanner.err"},
            "MONGO": {"enabled": "False", "URI": "mongodb://localhost"},
            "LOCALLOG": {"enabled": "False", "PATH": "/tmp/user_tanner_report.json"},
            "CLEANLOG": {"enabled": "False"},
        }

        self.valid_config_path = "/tmp/tanner_config"
        self.cfg = configparser.ConfigParser()
        if not os.path.exists(self.valid_config_path):
            for section in self.d:
                self.cfg.add_section(section)
                for value, data in self.d[section].items():
                    self.cfg.set(section, value, data)
            f = open(self.valid_config_path, "w")
            self.cfg.write(f)
        else:
            self.cfg.read(self.valid_config_path)

        self.invalid_config_path = "/random/random_name"

    @mock.patch("tanner.tests.test_config.config")
    def test_set_config_when_file_exists(self, m):
        config.TannerConfig.set_config(self.valid_config_path)
        self.assertIsNotNone(config.TannerConfig.config)

    def test_set_config_when_file_dont_exists(self):
        with self.assertRaises(SystemExit):
            config.TannerConfig.set_config(self.invalid_config_path)
        self.assertIsNone(config.TannerConfig.config)

    def test_get_when_file_exists(self):
        config.TannerConfig.config = self.cfg
        for section in self.d:
            for value, assertion_data in self.d[section].items():

                convert_type = type(self.d[section][value])
                if convert_type is bool:
                    data = config.TannerConfig.config.getboolean(section, value)
                else:
                    data = config.TannerConfig.config.get(section, value)
                self.assertEqual(data, convert_type(assertion_data))

    def test_get_when_file_dont_exists(self):
        with open("/opt/tanner/data/config.yaml", "r") as f:
            config_template = yaml.load(f, Loader=yaml.FullLoader)

        for section in config_template:
            for value, assertion_data in config_template[section].items():
                data = config.TannerConfig.get(section, value)
                self.assertEqual(data, assertion_data)
