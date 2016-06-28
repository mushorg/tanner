Sessions
========

.. _session:
Session
~~~~~~~
Session class accepts ``data`` as a parameter. The ``data`` came from SNARE and  is validated  before use (see :ref:`session-manager`).

**Attributes:**

    * **ip** -- peer ip address.
    * **port** -- peer port.
    * **user_agent** -- peer user agent.
    * **sensor** -- SNARE sensor uuid.
    * **paths** -- list of dictionaries. Contains ``path``, ``timestamp``, ``attack_type`` and SNARE ``response status``.
    * **uuid** -- randomly generated session uuid.
    * **start_timestamp** -- session start time.
    * **timestamp** -- current session timestamp.
    * **count** -- count of the session's updates (i.e. requested paths).

 ``KEEP_ALIVE_TIME`` is the constant, which set up the active session time. Default value is 75.
 After this time, the session is expired and can be deleted.


.. _session-manager:

Session Manager
~~~~~~~~~~~~~~~
Every session is tracking and recording.

The session is determined by peer ``ip`` and ``user_agent``.
Session is unique, if there is no sessions with this ``ip`` and ``user_agent``.
If session exists, it will be updated.
Active sessions are kept in the process memory (see :ref:`session`). After expiration, session is pushed into the Redis (see :doc:`storage`)

Data validation
"""""""""""""""
If necessary fields missing in the raw data from SNARE, these fields are created
with ``None`` value.


Session Evaluation
~~~~~~~~~~~~~~~~~~
When session is deleted from python process memory, it is evaluated by session analyzer.
The result contains next fields:

* *Session attributes*
    * **uuid** --
    * **peer_ip**
    * **peer_port**
    * **user_agent**
    * **sensor_uuid**
    * **start_time**
* **end_time** -- last session timestamp
* **requests_per_second** -- request per second from user
* **approx_time_between_requests** --
* **accepted_paths** -- number of accepted paths
* **errors** -- counts of errors in SNARE responses
* **hidden_links** -- count of accepted dorks hidden links
* **attack_types** -- list of attack types
* **paths** -- list of all paths
* **possible_owners** -- list of possible owners. May be ``user``, ``attacker``, ``tool`` and ``crawler``



