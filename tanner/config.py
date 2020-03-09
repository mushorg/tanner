import logging
import os
import sys

import yaml

LOGGER = logging.getLogger(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(HERE, "config.yaml")


def read_config(path):
    with open(path, 'r') as f:
        try:
            config_values = yaml.load(f, Loader=yaml.FullLoader)
        except yaml.YAMLError as e:
            print(e)

    return config_values


class TannerConfig():
    config = None

    @staticmethod
    def set_config(config_path, default=True):
        if not default:
            if not os.path.exists(config_path):
                print("Config file {} doesn't exist. Check the config path or use default".format(
                    config_path))
                sys.exit(1)

            TannerConfig.config = read_config(config_path)
        else:
            TannerConfig.config = read_config(DEFAULT_CONFIG)

    @staticmethod
    def get(section, value):
        res = None
        if TannerConfig.config is not None:
            config = TannerConfig.config
        else:
            config = read_config(DEFAULT_CONFIG)

        if section in config and value in config[section]:
            res = config[section][value]
        else:
            print("No such section found in the config file.")

        return res

    @staticmethod
    def get_section(section):
        res = {}
        if TannerConfig.config is not None:
            config = TannerConfig.config
        else:
            config = read_config(DEFAULT_CONFIG)
        
        res = config[section]
        return res
