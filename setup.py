#!/usr/bin/env python
from setuptools import find_packages, setup

setup(
    name="Tanner",
    version="0.6.0",
    description="He who flays the hide",
    author="MushMush Foundation",
    author_email="glastopf@public.honeynet.org",
    url="https://github.com/mushorg/tanner",
    packages=find_packages(exclude=["*.pyc"]),
    scripts=["bin/tanner", "bin/tannerweb", "bin/tannerapi"],
    data_files=[
        ("/opt/tanner/db/", ["tanner/data/db_config.json", "tanner/data/GeoLite2-City.mmdb"]),
        (
            "/opt/tanner/data/",
            [
                "tanner/data/dorks.pickle",
                "tanner/data/crawler_user_agents.txt",
                "tanner/files/engines/mako.py",
                "tanner/files/engines/tornado.py",
                "tanner/data/config.yaml",
            ],
        ),
    ],
)
