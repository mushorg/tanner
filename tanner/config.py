import configparser
import os


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
        config['DATA'] = {'db_config': '/opt/tanner/db/db_config.json', 'dorks': '/opt/tanner/data/dorks.pickle',
                          'user_dorks': '/opt/tanner/data/user_dorks.pickle',
                          'vdocs': '/opt/tanner/data/vdocs.json'}
        config['TANNER'] = {'host': '0.0.0.0', 'port': 8090}
        config['REDIS'] = {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1}
        config['EMULATORS'] = {'root_dir': '/opt/tanner'}
        config['SQLI'] = {'db_name': 'tanner.db'}
        config['LOGGER'] = {'log_file': '/opt/tanner/tanner.log'}
        config['MONGO'] = {'enabled': 'False', 'URI': 'mongodb://localhost'}
        config['LOCALLOG'] = {'enabled': 'False', 'PATH': '/tmp/tanner_report.json'}
        TannerConfig.write_config(config_path, config)
