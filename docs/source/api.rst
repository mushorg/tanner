Tanner API
==========
Tanner api provides various stats related to traffic captured by snare. It can be accessed at ``locahost:8090/api/``.

api/
~~~~
This is the index page which shows ``tanner api``.

api/snares
~~~~~~~~~~
This shows all the snares' uuid.

api/snare/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show all the sessions related to that ``snare-uuid`` and their details.

api/snare-stats/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will show some stats.

	* No of sessions in the sanre
	* Total duration for which snare remains active
	* Attack frequency, which shows no of sessions which face different attacks.

/api/sessions?filters=<filters>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This shows all the sessions' uuid which follow the filters.
Filters are sepatated by ``white-space`` and name-value pair are separated by ``:``. E.g ``?filters=filter1:value1 filter2:value2``.

It supports 5 filters:

	* **snare_uuid** -- Sessions related to given snare. E.g ``?filters=snare_uuid:8fa6aa98-4283-4085-bfb9-a1cd3a9e56e7``
	* **peer_ip** -- Sessions with given ip. E.g ``?filters=peer_ip:127.0.0.1``
	* **user-agent** -- Sessions with given user-agent. E.g ``?filters=user-agent:Chrome``
	* **attack_type** -- Sessions with given attack type such as lfi, rfi, xss, cmd_exec, sqli. E.g ``?filters=attack_type:lfi``
	* **owner_type** -- Sessions with given owner type such as user, tool, crawler, attacker. E.g ``?filters=owner_type:attacker``
	* **time_interval** -- Sessions which are active during a given time-interval. E.g ``?filters=time_interval:1480560-1480580``

/api/session/<sess-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~
It gives all information about the session with given uuid.