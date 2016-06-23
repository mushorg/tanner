Dorks
=====

There are two types of the dorks:

* **Manually added dorks** -- came from the Google Hacking database and other sources
* **User dorks** -- all user requests with queries

All dorks are stored in the Redis and keys for the dorks are static:

* **Manually dorks**  -- ``uuid.uuid3(uuid.NAMESPACE_DNS,'dorks').hex``.
* **User dorks** -- ``uuid.uuid3(uuid.NAMESPACE_DNS,'user_dorks').hex``.

On initializing stage, Dorks Manager loads manually added dorks (``dorks.pickle``) from project directory and push them into redis.
Dorks are stored in the Redis as ``set`` to avoid repetition.


