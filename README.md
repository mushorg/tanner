TANNER
======
[![Documentation Status](https://readthedocs.org/projects/tanner/badge/?version=latest)](http://tanner.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/tanner/badge.svg?branch=master)](https://coveralls.io/github/mushorg/tanner?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/tanner/badge.svg?branch=develop)](https://coveralls.io/github/mushorg/tanner?branch=develop)

<b><i>He who flays the hide</b></i>


About
-----
TANNER is a remote data analysis and classification service to evaluate HTTP requests and composing the response then served by [SNARE](https://github.com/mushorg/snare). TANNER uses multiple application vulnerability type emulation techniques when providing responses for SNARE. In addition, TANNER provides Dorks for SNARE powering its luring capabilities.


Documentation
-------------
The documentation can be found [here](http://tanner.readthedocs.io).


Basic Concept
-------------

- Evaluating [SNARE](https://github.com/mushorg/snare) events.
- Serve dorks.
- Emulate vulnerabilities and provide responses.


Getting Started
---------------

- You need Python3.7 and above for installing tanner.
- This was tested with a recent Ubuntu-based Linux.

### Steps to install TANNER

#### Step 1: Setup Redis

1. Install the Redis: ``sudo apt-get install redis-server``
2. Run ``redis-server`` (to start it on `localhost` with default `port`)

#### Step 2: Setup PHP Sandbox

1. For PHP Sandbox setup, see sandbox [manual](https://github.com/mushorg/phpox)
2. In PHP Sandbox directory, run sandbox: ``sudo python3 sandbox.py``

#### Step 3: Setup Docker

1. Run ``sudo apt-get install docker-ce docker-ce-cli containerd.io``

For more info please see the detailed installation guide [here.](https://docs.docker.com/engine/installation/linux/ubuntu/)

#### Step 4: Setup and run TANNER

1. Get TANNER: `git clone https://github.com/mushorg/tanner.git`
2. Go to the TANNER source  directory: ``cd tanner``
3. Install requirements: `sudo pip3 install -r requirements.txt`
4. Install TANNER: ``sudo python3 setup.py install``
5. Run TANNER: ``sudo tanner``
6. (Optional) For runnning TANNER Api ``sudo tannerapi``
7. (Optional) For runnning TANNER Web ``sudo tannerweb``

Note:- Make sure you have `python3-dev` incase you are facing problem with installing some requirments.
```
  sudo apt-get install python3-dev
```

(Recommended) You should bind to 0.0.0.0 when running in <i>production</i> and on a different host than SNARE.

### Install and run TANNER using docker container

In case you want to run the TANNER service using docker or facing any problem
in setting up TANNER on your machine, you can follow these steps.

#### Docker build instructions
1. Change the current directory to `tanner/docker`
2. `sudo docker-compose build`
3. `sudo docker-compose up`

More information about running `docker-compose` can be found [here.](https://docs.docker.com/compose/gettingstarted/)

Testing
-------

In order to run the tests and receive a test coverage report, we recommend running `pytest`:

    pip install pytest pytest-cov
    sudo pytest --cov-report term-missing --cov=tanner tanner/tests/

Sample Output
-------------

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
