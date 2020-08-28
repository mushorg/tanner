Storage
==========

Tanner uses a combination of Postgres_ and Redis_ for storage purpose.


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

Until v0.7 we were using only Redis for storing so if you are currently using the just Redis for storage then you'll have to migrate all your data to the postgresql and have a properly configured database setup. To make your work easy we have made a migration-script_


.. _Redis: http://redis.io/
.. _Postgres: https://www.postgresql.org/
.. _migration-script: TODO ADD LINK HERE

