Configuration file
==================
Tanner uses ``INI`` like format for configuration file. It's value can specified by using ``config`` flag

There are 8 different sections :
  * **DATA**

    :db_config: Location of SQLI database configuration
    :dorks: Location of dorks
    :user_dorks: Location of user dorks
    :vdocs: Location of configuration file for virtual docs
  * **TANNER**

    :Host: The host at which Tanner is running
    :Port: The port at which Tanner is running
  * **REDIS**

    :Host: The host address at which redis is running
    :Post: The port at which which redis is running
    :Poolsize: The poolsize of redis server
    :timeout: The duration of timeout for redis server
  * **EMULATORS**

    :root_dir: The root directory for emulators that need data storing such as SQLI and LFI. Data will be stored in this directory
  * **SQLI**

    :db_name: THe name of database used in SQLI emulator
  * **CMD_EXEC**

    :host_image: The image which emulates commands in Command Execution Emulator
  * **LOGGER**

    :log_file: Location of tanner log file
  * **MONGO**

    :enabled: Check whether MONGO database is enabled
    :URI: URI for connecting to MONGO DB
  * **LOCALLOG**

    :enabled: Check local(temporary) logging is enabled
    :PATH: Location of file for local(temporary) logging

If no file is specified, following json will be used as default:

.. code-block:: python

    {'DATA': {'db_config': '/opt/tanner/db/db_config.json', 'dorks': '/opt/tanner/data/dorks.pickle',
              'user_dorks': '/opt/tanner/data/user_dorks.pickle',
              'vdocs': '/opt/tanner/data/vdocs.json'},
     'TANNER': {'host': '0.0.0.0', 'port': 8090},
     'REDIS': {'host': 'localhost', 'port': 6379, 'poolsize': 80, 'timeout': 1},
     'EMULATORS': {'root_dir': '/opt/tanner'},
     'SQLI': {'db_name': 'tanner.db'},
     'CMD_EXEC': {'host_image': 'busybox:latest'},
     'LOGGER': {'log_file': '/opt/tanner/tanner.log'},
     'MONGO': {'enabled': 'False', 'URI': 'mongodb://localhost'},
     'LOCALLOG': {'enabled': 'False', 'PATH': '/tmp/tanner_report.json'}
     }
