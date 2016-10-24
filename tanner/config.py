import configparser
import os


class TannerConfig():
    config = None

    @staticmethod
    def set_config(config_path):
        cfg = configparser.ConfigParser()
        if not os.path.exists(config_path):
            TannerConfig.create_default_config(cfg, config_path)

        cfg.read(config_path)
        TannerConfig.config = cfg

    @staticmethod
    def create_default_config(config, config_path):
        config['TANNER'] = {'host': '0.0.0.0', 'port': 8090}
        config['REDIS'] = {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1}
        config['EMULATORS'] = {'root_dir': '/opt/tanner'}
        config['SQLI'] = {'db_name': 'tanner.db'}
        with open(config_path, 'w') as configfile:
            config.write(configfile)
