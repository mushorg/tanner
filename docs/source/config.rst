Configuration file
==================
Tanner uses ``YAML`` like format for configuration file. It's value can specified by using ``config`` flag.

The use of ``INI`` configuration file is obsolete now.

There are 8 different sections :
  * **DATA**
    # Data configuration
    :db_config: Location of SQLI database configuration
    :dorks: Location of dorks
    :user_dorks: Location of user dorks
  * **TANNER**

    :host: The host at which Tanner is running
    :port: The port at which Tanner is running
  * **WEB**
    # Tanner web configuration
    :host: The host at which Tanner Web UI is running
    :port: The port at which Tanner Web UI is running
  * **API**
    # Tanner API configuration
    :Host: The host at which Tanner API is running
    :Port: The port at which Tanner API is running
  * **PHPOX**

    :Host: The host at which PHPOX is running
    :Port: The port at which PHPOX is running
  * **REDIS**
    # Configure redis if it's running on some different port or network.
    
    :host: The host address at which redis is running
    :port: The port at which which redis is running
    :poolsize: The poolsize of redis server
    :timeout: The duration of timeout for redis server
  * **EMULATORS**
    
    :root_dir: The root directory for emulators that need data storing such as SQLI and LFI. Data will be stored in this directory

    * **EMULATOR_ENABLED**
      # Enable or disable emulators by setting value true or false respectively.
      :sqli: True if this emulator is enabled else False
      :rfi: True if this emulator is enabled else False
      :lfi: True if this emulator is enabled else False
      :xss: True if this emulator is enabled else False
      :cmd_exec: True if this emulator is enabled else False

  * **SQLI**

    :type: Supports two types MySQL/SQLITE
    :db_name: The name of database used in SQLI emulator
    :host: This will be used for MySQL to get the host address
    :user: This is the MySQL user which perform DB queries
    :password: The password corresponding to the above user
  * **DOCKER**

    :host_image: The image which emulates commands in Command Execution Emulator and file system in LFI emulator
  * **LOGGER**

    :log_debug: Location of tanner log file
    :log_err: Location of tanner error file
  * **MONGO**

    :enabled: Check whether MONGO database is enabled
    :URI: URI for connecting to MONGO DB
  * **HPFEEDS**

    :enabled: Check whether HPFEEDS logging is enabled
    :HOST: IP address or name of the hpfeeds server
    :PORT: Port of the hpfeeds service
    :IDENT: Identifier of the hpfeeds client
    :SECRET: Secret of the hpfeeds client
    :CHANNEL: Channel to which publish messages
  * **LOCALLOG**

    :enabled: Check local(temporary) logging is enabled
    :PATH: Location of file for local(temporary) logging

If no file is specified, following YAML will be used as default:

.. code-block:: python

  DATA:
    db_config: /opt/tanner/db/db_config.json
    dorks: /opt/tanner/data/dorks.pickle
    user_dorks: /opt/tanner/data/user_dorks.pickle
    crawler_stats: /opt/tanner/data/crawler_user_agents.txt
    geo_db: /opt/tanner/db/GeoLite2-City.mmdb
    tornado: /opt/tanner/data/tornado.py
    mako: /opt/tanner/data/mako.py

  TANNER:
    host: 0.0.0.0
    port: 8090

  WEB:
    host: 0.0.0.0
    port: 8091,

  API:
    host: 0.0.0.0
    port: 8092
    auth: False
    auth_signature: tanner_api_auth

  PHPOX:
    host: 0.0.0.0
    port: 8088

  REDIS:
    host: localhost
    port: 6379
    poolsize: 80
    timeout: 1

  EMULATORS:
    root_dir: /opt/tanner

  EMULATOR_ENABLED:
    sqli: True
    rfi: True
    lfi: True
    xss: True
    cmd_exec: True
    php_code_injection: True
    php_object_injection: True
    crlf: True
    xxe_injection: True
    template_injection: True

  SQLI:
    type: SQLITE
    db_name: tanner_db
    host: localhost
    user: root
    password: user_pass

  XXE_INJECTION:
    OUT_OF_BAND: False

  RFI:
    allow_insecure: False

  DOCKER:
    host_image: busybox:latest

  LOGGER:
    log_debug: /opt/tanner/tanner.log
    log_err: /opt/tanner/tanner.err

  MONGO:
    enabled: False
    URI: mongodb://localhost

  HPFEEDS:
    enabled: False
    HOST: localhost
    PORT: 10000
    IDENT: ''
    SECRET: ''
    CHANNEL: tanner.events

  LOCALLOG:
    enabled: False
    PATH: /tmp/tanner_report.json

  CLEANLOG:
    enabled: False

  REMOTE_DOCKERFILE:
    GITHUB: "https://raw.githubusercontent.com/mushorg/tanner/master/docker/tanner/template_injection/Dockerfile"

  SESSIONS:
    delete_timeout: 300

