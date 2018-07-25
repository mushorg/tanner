Tanner API
==========
Tanner api provides various stats related to traffic captured by snare. It can be accessed at ``locahost:8092/?key=API_KEY``.

where, ``API_KEY`` is a JWT-token created by a particular tanner-api, which can be found during tanner-api startup: 

``API_KEY for full access: 'API_KEY'``

How to create an API_KEY with desired signature?
~~~~~~~~
* By default tanner's API_KEYs use the signature: 'tanner_api_auth'
* This signature is veryfied on all the API requests.
* It is highly recommended that every tanner-owner set their own signature.
* This can be done by modifying tanner.config['API']['auth_signature'] to the desired one.

/?key=API_KEY
~~~~
This is the index page which shows ``tanner api``.

/snares
~~~~~~~~~~
This shows all the snares' uuid.

/snare/<snare-uuid>?key=API_KEY
~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show all the sessions related to that ``snare-uuid`` and their details.

/snare-stats/<snare-uuid>?key=API_KEY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show some stats.

	* No of sessions in the sanre
	* Total duration for which snare remains active
	* Attack frequency, which shows no of sessions which face different attacks.

/<snare-uuid>/sessions?filters=<filters>&key=API_KEY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This shows all the sessions' uuid which follow the filters.
Filters are sepatated by ``white-space`` and name-value pair are separated by ``:``. E.g ``?filters=filter1:value1 filter2:value2``.

It supports 5 filters:

	* **peer_ip** -- Sessions with given ip. E.g ``peer_ip:127.0.0.1 ``
	* **user-agent** -- Sessions with given user-agent. E.g ``user-agent:Chrome``
	* **attack_types** -- Sessions with given attack type such as lfi, rfi, xss, cmd_exec, sqli. E.g ``attack_types:lfi``
	* **possible_owners** -- Sessions with given owner type such as user, tool, crawler, attacker. E.g ``possible_owners:attacker``
	* **start_time** -- Sessions which started after `start_time`. E.g ``start_time:1480560``
	* **end_time** -- Sessions which ended before `end_time`. E.g ``end_time:1480560``

Multiple filters can be applied as ``peer_ip:127.0.0.1 start_time:1480560 possible_owners:attacker``

/api/session/<sess-uuid>?key=API_KEY
~~~~~~~~~~~~~~~~~~~~~~~~
It gives all information about the session with given uuid.

External hyperlinks, like Python_.
.. _Python: http://www.python.org/
