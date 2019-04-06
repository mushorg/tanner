import configparser
import logging
import os
import sys

LOGGER = logging.getLogger(__name__)


class TannerConfig:
    config = None

    @staticmethod
    def set_config_template(base_dir='/opt/tanner'):
        global config_template
        config_template = {
            'DATA': {'db_config': '{}/db/db_config.json'.format(base_dir),
                     'dorks': '{}/data/dorks.pickle'.format(base_dir),
                     'user_dorks': '{}/data/user_dorks.pickle'.format(base_dir),
                     'crawler_stats': '{}/data/crawler_user_agents.txt'.format(base_dir),
                     'geo_db': '{}/db/GeoLite2-City.mmdb'.format(base_dir)
                     },
            'TANNER': {'host': '0.0.0.0', 'port': 8090},
            'WEB': {'host': '0.0.0.0', 'port': 8091},
            'API': {'host': '0.0.0.0', 'port': 8092},
            'PHPOX': {'host': '0.0.0.0', 'port': 8088},
            'REDIS': {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1},
            'EMULATORS': {'root_dir': base_dir},
            'EMULATOR_ENABLED': {'sqli': True, 'rfi': True, 'lfi': True, 'xss': True, 'cmd_exec': True,
                                 'php_code_injection': True, "crlf": True},
            'SQLI': {'type': 'SQLITE', 'db_name': 'tanner_db', 'host': 'localhost', 'user': 'root',
                     'password': 'user_pass'},
            'DOCKER': {'host_image': 'busybox:latest'},
            'LOGGER': {'log_debug': '{}/tanner.log'.format(base_dir), 'log_err': '{}/tanner.err'.format(base_dir)},
            'MONGO': {'enabled': False, 'URI': 'mongodb://localhost'},
            'HPFEEDS': {'enabled': False, 'HOST': 'localhost', 'PORT': 10000, 'IDENT': '', 'SECRET': '',
                        'CHANNEL': 'tanner.events'},
            'LOCALLOG': {'enabled': False, 'PATH': '/tmp/tanner_report.json'},
            'CLEANLOG': {'enabled': False}
        }

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
        res = None
        if TannerConfig.config is not None:
            try:
                convert_type = type(config_template[section][value])
                if convert_type is bool:
                    res = TannerConfig.config.getboolean(section, value)
                else:
                    res = convert_type(TannerConfig.config.get(section, value))
            except (configparser.NoOptionError, configparser.NoSectionError):
                LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section, value)
                res = config_template[section][value]

        else:
            res = config_template[section][value]
        return res

    @staticmethod
    def get_section(section):
        res = {}
        if TannerConfig.config is not None:
            try:
                sec = TannerConfig.config[section]
                for k, v in sec.items():
                    convert_type = type(config_template[section][k])
                    if convert_type is bool:
                        res[k] = TannerConfig.config[section].getboolean(k)
                    else:
                        res[k] = convert_type(v)
            except (configparser.NoOptionError, configparser.NoSectionError):
                LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section)
                res = config_template[section]

        else:
            res = config_template[section]

        return res


TannerConfig.set_config_template()
