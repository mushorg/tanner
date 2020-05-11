Quick Start
===========

TANNER, a remote data analysis and classification service, to evaluate HTTP requests and composing the response then
served by SNARE.

Basic concept
"""""""""""""

* Evaluating SNARE events.
* Serve dorks.
* Adopt and change the responses.

Setup Redis
"""""""""""

#. Install the Redis: ``sudo apt-get install redis-server``
#. Start it on ``localhost`` with default ``port``: ``redis-server``

Setup PHP Sanbox
""""""""""""""""

#. For PHP Sandbox setup, see sandbox manual_
#. In PHP Sandbox directory, run sandbox: ``sudo python3 sandbox.py``


.. _manual: https://github.com/mushorg/phpox

Setup and run TANNER
""""""""""""""""""""

#. Get TANNER: ``git clone https://github.com/mushorg/tanner.git``
#. Go to the tanner source directory ``cd tanner``
#. Install requirements: ``sudo pip3 install -r requirements.txt``
#. Install tanner ``sudo python3 setup.py install``
#. Run TANNER: ``sudo tanner``

Run Tanner Api
""""""""""""""

#. Run ``sudo tannerapi``

Run Tanner WebUI
""""""""""""""""

#. Run ``sudo tannerweb``

Docker build instructions
"""""""""""""""""""""""""
1. Change current directory to ``tanner/docker``
2. ``docker-compose build``
3. ``docker-compose up``

**Note**: Running docker with default ``docker-compose.yml`` setting will start tanner, tannerapi, tannerweb, tanner redis, tannerphpox but only tanner and tannerweb will be accesible from the outside network.

More information about running ``docker-compose`` can be found `here <https://docs.docker.com/compose/gettingstarted/>`_.
