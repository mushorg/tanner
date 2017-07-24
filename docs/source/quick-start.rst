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
#. Install requirements: ``pip3 install -r requirements.txt``
#. Install tanner ``python3 setup.py install``
#. Run TANNER: ``sudo tanner``

Run Tanner Api
""""""""""""""

#. Run ``sudo tannerapi``

Run Tanner WebUI
""""""""""""""""

#. Run ``sudo tannerweb``