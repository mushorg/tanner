TANNER [![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)
======

<b>He who flays the hide</b>


Basic Concept
-------------

- Evaluating [SNARE](https://github.com/mushorg/snare) events.
- Serve dorks.
- Adopt and change the responses.


Getting Started
---------------

- You need Python3. We tested primarily with **python 3.5**
- This was tested with a recent Ubuntu based Linux.


### Setup Redis


1. Install the Redis: ``sudo apt-get install redis-server``
2. Start it on ``localhost`` with default ``port``: ``redis-server``

### Setup PHP Sanbox


1. For PHP Sandbox setup, see sandbox [manual] (https://github.com/mushorg/phpox)
2. In PHP Sandbox directory, run sandbox: ``sudo python3 sandbox.py``


### Setup Libinjection

1. Install swig ``sudo apt-get install swig``
2. Clone Libinjection from [git] (https://github.com/client9/libinjection)
3. Install libinjection for Python ``cd libinjection/python && make && make install``


### Setup and run TANNER


1. Get TANNER: `git clone https://github.com/mushorg/tanner.git`
2. Go to the TANNER source  directory: ``cd tanner`` 
3. Install requirements: `pip3 install -r requirements.txt`
4. Install TANNER: ``python3 setup.py install``
5. Run TANNER: ``sudo tanner``

You obviously want to bind to 0.0.0.0 when running in <i>production</i> and on a different host than SNARE (recommended).

[See the docs for more info](docs/source/index.rst)
