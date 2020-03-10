import logging
import os
import sys

import yaml

LOGGER = logging.getLogger(__name__)


def read_config(path):
    config_values = {}
    with open(path, 'r') as f:
        config_values = yaml.load(f, Loader=yaml.FullLoader)
    return config_values


DEFAULT_CONFIG = read_config("/opt/tanner/data/config.yaml")


class TannerConfig():
    config = None

    @staticmethod
    def set_config(config_path):
        if not os.path.exists(config_path):
            print("Config file {} doesn't exist. Check the config path or use default".format(
                config_path))
            sys.exit(1)

        TannerConfig.config = read_config(config_path)

    @staticmethod
    def get(section, value):
        if TannerConfig.config is not None:
            try:
                res = TannerConfig.config[section][value]
            except KeyError:
                res = DEFAULT_CONFIG[section][value]
        else:
            res = DEFAULT_CONFIG[section][value]

        return res

    @staticmethod
    def get_section(section):
        res = {}
        if TannerConfig.config is not None:
            res = TannerConfig.config[section]
        else:
            res = DEFAULT_CONFIG[section]

        return res
