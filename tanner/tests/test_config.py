import configparser
import os
import unittest

from tanner import config


class TestCongif(unittest.TestCase):
    def setUp(self):
        config.TannerConfig.config = None
        self.d = {
            'DATA': {'db_config': '/tmp/user_tanner/db/db_config.json', 'dorks': '/tmp/user_tanner/data/dorks.pickle',
                     'user_dorks': '/tmp/user_tanner/data/user_dorks.pickle',
                     'vdocs': '/tmp/user_tanner/data/vdocs.json'},
            'TANNER': {'host': '0.0.0.0', 'port': '9000'},
            'REDIS': {'host': 'localhost', 'port': '1337', 'poolsize': '40', 'timeout': '5'},
            'EMULATORS': {'root_dir': '/tmp/user_tanner'},
            'SQLI': {'db_name': 'user_tanner.db'},
            'LOGGER': {'log_file': '/tmp/user_tanner/user_tanner.log'},
            'MONGO': {'enabled': 'False', 'URI': 'mongodb://localhost'},
            'LOCALLOG': {'enabled': 'False', 'PATH': '/tmp/user_tanner_report.json'}
            }

        self.valid_config_path = '/tmp/tanner_config'
        self.cfg = configparser.ConfigParser()
        if not os.path.exists(self.valid_config_path):
            for section in self.d:
                self.cfg.add_section(section)
                for value, data in self.d[section].items():
                    self.cfg.set(section, value, data)
            f = open(self.valid_config_path, 'w')
            self.cfg.write(f)
        else:
            self.cfg.read(self.valid_config_path)

        self.invalid_config_path = '/random/random_name'

    def test_set_config_when_file_exists(self):
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
                data = config.TannerConfig.get(section, value)
                self.assertEqual(data, assertion_data)

    def test_get_when_file_dont_exists(self):
        config_template = {
            'DATA': {'db_config': '/opt/tanner/db/db_config.json', 'dorks': '/opt/tanner/data/dorks.pickle',
                     'user_dorks': '/opt/tanner/data/user_dorks.pickle',
                     'vdocs': '/opt/tanner/data/vdocs.json'},
            'TANNER': {'host': '0.0.0.0', 'port': 8090},
            'REDIS': {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1},
            'EMULATORS': {'root_dir': '/opt/tanner'},
            'SQLI': {'db_name': 'tanner.db'},
            'LOGGER': {'log_file': '/opt/tanner/tanner.log'},
            'MONGO': {'enabled': 'False', 'URI': 'mongodb://localhost'},
            'LOCALLOG': {'enabled': 'False', 'PATH': '/tmp/tanner_report.json'}
            }

        for section in config_template:
            for value, assertion_data in config_template[section].items():
                data = config.TannerConfig.get(section, value)
                self.assertEqual(data, assertion_data)
