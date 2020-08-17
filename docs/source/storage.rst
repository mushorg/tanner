Old Method
==========
Until Tanner v0.7 we were using Redis_ for storing all the data i.e analyzed and unanalyzed sessions. But the issue with that Redis was that it's a ``in-memory`` database meaning it consume large amount of RAM if large amount of data has to be stored. This usually resulted in the unexpected crash of the tanner server.


New Method
==========

To solve the problem described above we decided to use the combination of Postgres_ and Redis_ for storage purpose.


**Setup Both database**

* Installation

    * Install Redis
        #. On ubuntu: ``sudo apt-get install redis-server``

    * Install Postgres
        #. On ubuntu: ``sudo apt install postgresql``

* Configuration

Once both the server are installed and are running, make the required changes to configuration file which should be present in `/opt/tanner/config.yaml`. See [config] section for more detail about configuration file.

Migrating from old setup to new setup
=====================================

If you are currently using the old setup for tanner then you'll have to migrate all your data to the postgresql and have a properly configured database setup. To make your work easy we have made a migration-script_


.. _Redis: http://redis.io/
.. _Postgres: https://www.postgresql.org/
.. _migration-script: TODO ADD LINK HERE

