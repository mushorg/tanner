import configparser
import os
import io
import logging

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
    def write_config(filename, cfg):
        with open(filename, 'w') as configfile:
            cfg.write(configfile)

    @staticmethod
    def set_config(config_path):
        cfg = configparser.ConfigParser()
        if not os.path.exists(config_path):
            TannerConfig.create_default_config(cfg, config_path)

        cfg.read(config_path)
        TannerConfig.config = cfg

    @staticmethod
    def create_default_config(config, config_path):
        buf = io.StringIO(config_template)
        config.readfp(buf)
        TannerConfig.write_config(config_path, config)

    @staticmethod
    def get(section, value):
        try:
            res = TannerConfig.config.get(section, value)
        except (configparser.NoOptionError, configparser.NoSectionError):
            LOGGER.warning("Error in config, default value will be used. Section: %s Value: %s", section, value)
            res = config_template[section][value]
        return res
