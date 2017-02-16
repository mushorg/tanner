import configparser
import logging
import os
import sys

LOGGER = logging.getLogger(__name__)
config_template = {'DATA': {'db_config': '/opt/tanner/db/db_config.json', 'dorks': '/opt/tanner/data/dorks.pickle',
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
        try:
            res = TannerConfig.config.get(section, value)
        except (configparser.NoOptionError, configparser.NoSectionError, AttributeError):
            LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section, value)
            res = config_template[section][value]
        return res
