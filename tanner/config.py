import configparser
import logging
import os
import sys

LOGGER = logging.getLogger(__name__)

config_template = {'DATA': {'db_config': '/opt/tanner/db/db_config.json', 'dorks': '/opt/tanner/data/dorks.pickle',
                            'user_dorks': '/opt/tanner/data/user_dorks.pickle'},
                   'TANNER': {'host': '0.0.0.0', 'port': 8090},
                   'WEB': {'host': '0.0.0.0', 'port': 8091},
                   'API': {'host': '0.0.0.0', 'port': 8092},
                   'PHPOX': {'host': '0.0.0.0', 'port': 8088},
                   'REDIS': {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1},
                   'EMULATORS': {'root_dir': '/opt/tanner'},
                   'EMULATOR_ENABLED': {'sqli': True, 'rfi': True, 'lfi': True, 'xss': True, 'cmd_exec': True, 'php_code_injection': True, "crlf":True},
                   'SQLI': {'type':'SQLITE', 'db_name': 'tanner_db', 'host':'localhost', 'user':'root', 'password':'user_pass'},
                   'DOCKER': {'host_image': 'busybox:latest'},
                   'LOGGER': {'log_debug': '/opt/tanner/tanner.log', 'log_err': '/opt/tanner/tanner.err'},
                   'MONGO': {'enabled': False, 'URI': 'mongodb://localhost'},
                   'HPFEEDS': {'enabled': False, 'HOST': 'localhost', 'PORT': 10000, 'IDENT': '', 'SECRET': '', 'CHANNEL': 'tanner.events'},
                   'LOCALLOG': {'enabled': False, 'PATH': '/tmp/tanner_report.json'},
                   'CLEANLOG': {'enabled': False}
                   }


class TannerConfig():
    config = None

    @staticmethod
    def set_config(config_path):
        cfg = configparser.ConfigParser()
        if not os.path.exists(config_path):
            print("Config file {} doesn't exist. Check the config path or use default".format(config_path))
            sys.exit(1)

        cfg.read(config_path)
        TannerConfig.config = cfg

    @staticmethod
    def get(section, value):
        if TannerConfig.config is not None:
            try:
                convert_type = type(config_template[section][value]) 
                res = convert_type(TannerConfig.config.get(section, value))
            except (configparser.NoOptionError, configparser.NoSectionError):
                LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section, value)
                res = config_template[section][value]
            return res
        else:
            return config_template[section][value]

    @staticmethod
    def get_section(section):
        if TannerConfig.config is not None:
            try:
                res = TannerConfig.config[section]
            except (configparser.NoOptionError, configparser.NoSectionError):
                LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section)
                res = config_template[section]
            return res
        else:
            return config_template[section]
