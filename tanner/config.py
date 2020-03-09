import logging
import os
import sys

import yaml

LOGGER = logging.getLogger(__name__)


class TannerConfig():

    def __init__(self):
        self.config = None

    def read_config(self, config_path):
        with open(config_path, 'r') as f:
            try:
                config_values = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(e)

        return config_values

    def set_config(self, config_path, default=True):
        if not default:
            if not os.path.exists(config_path):
                print("Config file {} doesn't exist. Check the config path or use default".format(
                    config_path))
                sys.exit(1)

            self.config = self.read_config(config_path)
        else:
            self.config = self.read_config("config.yaml")

    def get(self, section, value):
        if section in self.config:
            for v in self.config[section]:
                if value in v:
                    res = v[value]
        else:
            print("No such section found in the config file.")

        return res

    def get_section(self, section):
        res = dict((key, d[key]) for d in self.config[section] for key in d)
        return res
