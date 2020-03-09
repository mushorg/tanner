import logging
import os
import sys

import yaml

LOGGER = logging.getLogger(__name__)


def read_config(path):
    with open(path, 'r') as f:
        config_values = yaml.load(f, Loader=yaml.FullLoader)
    return config_values


class Meta(type):
    def __new__(cls, clsname, superclasses, attribs):
        def parse_default_configs(path):
            return read_config(path)

        default_config = parse_default_configs("/opt/tanner/config.yaml")
        attribs.update({
            'default_config': default_config,
            'parse_default_configs': parse_default_configs
        })

        return super(Meta, cls).__new__(cls, clsname, superclasses, attribs)


class TannerConfig(metaclass=Meta):
    config = None

    @staticmethod
    def set_default_config(default_config_path):
        TannerConfig.default_config = read_config("/opt/tanner/config.yaml")

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
                res = TannerConfig.default_config[section][value]
        else:
            res = TannerConfig.default_config[section][value]

        return res

    @staticmethod
    def get_section(section):
        res = {}
        if TannerConfig.config is not None:
            res = TannerConfig.config[section]
        else:
            res = TannerConfig.default_config[section]

        return res
