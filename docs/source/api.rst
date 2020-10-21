Tanner API
==========
Tanner api provides various stats related to traffic captured by snare. It can be accessed at ``locahost:8092/?key=API_KEY``.

where, ``API_KEY`` is a JWT-token created by a particular tanner-api, which can be found during tanner-api startup: 

``API_KEY for full access: 'API_KEY'``

How to create an API_KEY with desired signature?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* By default tanner's API_KEYs use the signature: 'tanner_api_auth'
* This signature is veryfied on all the API requests.
* It is highly recommended that every tanner-owner set their own signature.
* This can be done by modifying tanner.config['API']['auth_signature'] to the desired one.


Using API Key
~~~~~~~~~~~~~

.. code-block::

	/?key=API_KEY

This is the index page which shows ``tanner api``.

List Snare instances
~~~~~~~~~~~~~~~~~~~~
.. code-block::

	/snares

This shows all the snares' uuid.

Access single snare instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::

	/snare/<snare-uuid>?key=API_KEY


Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show all the sessions related to that ``snare-uuid`` and their details.

Stats of a snare instance
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block::

	/snare-stats/<snare-uuid>?key=API_KEY

Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show some stats.

	* No of sessions in the sanre
	* Total duration for which snare remains active
	* Attack frequency, which shows no of sessions which face different attacks.

List all sessions
~~~~~~~~~~~~~~~~~

.. code-block::

	/<snare-uuid>/<sessions-id>/?API_KEY

This gives you a list of all the sessions UUID that are present on a give snare instance.


Get single session
~~~~~~~~~~~~~~~~~~~
.. code-block::

	/session/<sess-uuid>?key=API_KEY

It gives all information about the session with given uuid.

Get all information about all the sessions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/<snare-uuid>/sessions?filters=<filters>&key=API_KEY
This shows all the sessions' uuid which follow the filters.
Filters are sepatated by ``white-space`` and name-value pair are separated by ``:``. 

E.g ``?filters=filter1:value1 filter2:value2``.

It supports 5 filters:

* **peer_ip** -- Sessions with given ip. 
	E.g  ``peer_ip:127.0.0.1``
* **user_agent** -- Sessions with given user-agent. 
	E.g ``user_agent:Chrome``
* **attack_type** -- Sessions with given attack type such as lfi, rfi, xss, cmd_exec, sqli. 
	E.g ``attack_types:lfi``
* **owners** -- Sessions with given owner type such as user, tool, crawler, attacker. 
	E.g ``owners:attacker``
* **start_time** -- Sessions which started after `start_time`. 
	E.g ``start_time:26-06-2020``
* **end_time** -- Sessions which ended before `end_time`. 
	E.g ``end_time:26-06-2020``

**Multiple filters** can be applied as ``peer_ip:127.0.0.1 start_time:26-06-2020 owners:attacker``

