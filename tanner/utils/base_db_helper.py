import json
import logging
import random

import mimesis

from tanner.config import TannerConfig


class BaseDBHelper:
    def __init__(self):
        self.logger = logging.getLogger("tanner.base_db_helper.BaseDBHelper")

    def read_config(self):
        with open(TannerConfig.get("DATA", "db_config")) as db_config:
            try:
                config = json.load(db_config)
            except json.JSONDecodeError as json_error:
                self.logger.info("Failed to load json: %s", json_error)
            else:
                return config

    @staticmethod
    def generate_dummy_data(data_tokens):
        """
        Insert dummy data based on data tokens
        I - integer id
        L - login/username
        E - email
        P - password
        T - piece of text
        :return:
        """

        token_list = data_tokens.split(",")

        samples_count = random.randint(100, 1000)
        inserted_data = []
        for i in range(samples_count):
            values = []
            person = mimesis.Person("en")
            for token in token_list:
                person = mimesis.Person()
                if token == "I":
                    values.append(i)
                if token == "L":
                    data = person.username()
                    values.append(data)
                if token == "E":
                    data = person.email()
                    values.append(data)
                if token == "P":
                    data = person.password()
                    values.append(data)
                if token == "T":
                    sample_length = random.randint(1, 10)
                    data = mimesis.Text().text(quantity=sample_length)
                    values.append(data)
            inserted_data.append(tuple(values))

        return inserted_data, token_list
