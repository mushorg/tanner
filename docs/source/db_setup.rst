DB Setup
========

To setup a database for sqli emulation TANNER provides ``db_config.json`` file, which stores the configuration of a database.
``db_config.json`` has the following structure:

::

    {
        "name": "db name"
        "tables":[
            {
                "table name": "name of the table"
                "schema": "the result of sqlite3 command .schema, create table expression"
                "data_tokens": "types of data in the columns"
            }
        ]
    }


Default ``db_config.json``:

::

    {
      "name": "test1",
      "tables": [
        {
          "table_name": "users",
          "schema": "CREATE TABLE users (id INTEGER PRIMARY KEY, username text, email text, password text);",
          "data_tokens": "I,L,E,P"
        },
        {
          "table_name": "comments",
          "schema": "CREATE TABLE comments (id INTEGER PRIMARY KEY, comment text);",
          "data_tokens": "I,T"
        }
      ]
    }

You can change default config to make your own db structure.

Data tokens
~~~~~~~~~~~

Data tokens are used for filling the database with dummy data.
There are 4 default tokens:
        * **I** -- integer id
        * **L** -- login/username
        * **E** -- email
        * **P** -- password
        * **T** -- piece of text


**Note**: TANNER uses the default linux wordlist (``/usr/share/dict/words``) for data.
If you don't have the default wordlist in your system, install it or put it manually in ``/usr/share/dict``.