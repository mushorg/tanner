Tanner WEB
==========
Tanner WEB provides various stats related to traffic captured by snare in UI form. It can be accessed at ``locahost:8091/``.

/
~~~~
This is the index page which has a logo (mushorg) with ``Tanner web`` written below it.

Below that we can find general info of the tanner instance:

* **Tanner version** -- Which shows the version of tanner instance
* **No. of snares connected** -- Which shows the number of snares connected to the tanner instance
* **Latest session** -- Which will navigate you to the latest session's info page
Below that we can find a clickable which states, ``Click here to navigate to snares list``, clicking which will move you to the ``/snares`` page.

/snares
~~~~~~~~~~ 
This shows all the snares' uuid. Each snare object is clickable. Clicking displays the page **/snare/<snare-uuid>**

/snare/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~
Replace ``<snare-uuid>`` with a valid `snare-uuid` and it will provide two options:
	* **Snare-Stats** -- It will move you to **/snare-stats/<snare-uuid>**
	* **Sessions** -- It will move you to **/<snare-uuid>/sessions**

/snare-stats/<snare-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~~
This page shows some general stats about the snare

	* **No of Sessions** - Total no of sessions of the snare
	* **Total Duration** - Total durations during which sessions remain active
	* **Attack Frequency** - Frequency of different attacks made on the snare

/<snare-uuid>/sessions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This shows all the sessions' uuid. Each is clickable. Clicking displays **/session/<sess-uuid>**
Filters can be on the sessions using the input box and clicking the ``Apply`` button.
Filters are sepatated by ``white-space`` and name-value pair are separated by ``:``. E.g ``filter1:value1 filter2:value2``.

It supports 6 filters:
	* **peer_ip** -- Sessions with given ip. E.g ``peer_ip:127.0.0.1 ``
	* **user-agent** -- Sessions with given user-agent. E.g ``user-agent:Chrome``
	* **attack_types** -- Sessions with given attack type such as lfi, rfi, xss, cmd_exec, sqli. E.g ``attack_types:lfi``
	* **possible_owners** -- Sessions with given owner type such as user, tool, crawler, attacker. E.g ``possible_owners:attacker``
	* **start_time** -- Sessions which started after `start_time`. E.g ``start_time:1480560``
	* **end_time** -- Sessions which ended before `end_time`. E.g ``end_time:1480560``
	* **location** -- Sessions which have been done from the specified geometric `location`. It can take value of either country, city, country_code or zip_code. E.g ``location:India``, ``location:Mumbai``, ``location:US``, ``location:636005`` etc

Multiple filters can be applied as ``peer_ip:127.0.0.1 start_time:1480560 possible_owners:attacker``

/session/<sess-uuid>
~~~~~~~~~~~~~~~~~~~~~~~~
It gives all information about the session with given uuid. Here you may find some of the text clickable such as 
``peer_ip``,``possible_owners``, ``start_time``, ``end_time``, ``attack_types``. Clicking on them will display all the sessions will same attribute value.
