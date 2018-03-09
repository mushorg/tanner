TANNER 
======
[![Documentation Status](https://readthedocs.org/projects/tanner/badge/?version=latest)](http://tanner.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)

<b><i>He who flays the hide</b></i>

About
--------
TANNER is a remote data analysis, and classification service, to evaluate HTTP requests and composing the response then served by [SNARE](https://github.com/mushorg/snare) events.

Documentation
---------------
The build of the documentations [source](https://github.com/mushorg/tanner/tree/master/docs/source) can be found [here](http://tanner.readthedocs.io).

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

### Setup PHP Sandbox


1. For PHP Sandbox setup, see sandbox [manual](https://github.com/mushorg/phpox)
2. In PHP Sandbox directory, run sandbox: ``sudo python3 sandbox.py``

### Setup Docker


1. Install [docker](https://docs.docker.com/engine/installation/linux/ubuntu/)
2. Pull the required image to use [default : ``busybox:latest``]

### Setup and run TANNER


1. Get TANNER: `git clone https://github.com/mushorg/tanner.git`
2. Go to the TANNER source  directory: ``cd tanner`` 
3. Install requirements: `pip3 install -r requirements.txt`
4. Install TANNER: ``sudo python3 setup.py install``
5. Run TANNER: ``sudo tanner``

### Run Tanner Api

Run ``sudo tannerapi``

### Run Tanner WebUI

Run ``sudo tannerweb``

You obviously want to bind to 0.0.0.0 when running in <i>production</i> and on a different host than SNARE (recommended).

## Sample Output


```shell
    # sudo tanner
    
           _________    _   ___   ____________
          /_  __/   |  / | / / | / / ____/ __ \
           / / / /| | /  |/ /  |/ / __/ / /_/ /
          / / / ___ |/ /|  / /|  / /___/ _, _/
         /_/ /_/  |_/_/ |_/_/ |_/_____/_/ |_|

    
     Debug logs will be stored in /opt/tanner/tanner.log
     Error logs will be stored in /opt/tanner/tanner.err
     ======== Running on http://0.0.0.0:8090 ========
     (Press CTRL+C to quit)
     
```
