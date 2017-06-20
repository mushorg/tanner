#!/usr/bin/env python
from setuptools import find_packages
from distutils.core import setup

setup(name='Tanner',
      version='0.2.0',
      description='He who flays the hide',
      author='MushMush Foundation',
      author_email='glastopf@public.honeynet.org',
      url='https://github.com/mushorg/tanner',
      packages=find_packages(exclude=['*.pyc']),
      scripts=['bin/tanner'],
      data_files=[('/opt/tanner/data/',['tanner/data/dorks.pickle'])]
      )