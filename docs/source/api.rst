Tanner API
==========
Tanner api provides various stats related to traffic captured by snare. It can be accessed at ``locahost:8092/``.

/
~~~~
This is the index page which shows ``tanner api``.

/snares
~~~~~~~~~~
This shows all the snares' uuid.

/snare/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show all the sessions related to that ``snare-uuid`` and their details.

/snare-stats/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show some stats.

	* No of sessions in the sanre
	* Total duration for which snare remains active
	* Attack frequency, which shows no of sessions which face different attacks.

/<snare-uuid>/sessions?filters=<filters>
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

/api/session/<sess-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~
It gives all information about the session with given uuid.