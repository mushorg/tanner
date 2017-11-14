Emulators
---------
Base emulator
~~~~~~~~~~~~~
This is the heart of emulation. Current emulators follow ``find and emulate`` approach where each emulator has a ``scan`` method
which is called by base emulator against each ``GET``, ``POST`` parameter and ``cookie value``. The parameter which is affected, gets
emulated by calling the corresponding emulator's ``handle`` method. It returns the ``payload`` along with ``injection page`` which is most recently visited ``text/html`` type page.

RFI emulator
~~~~~~~~~~~~
It emulates RFI_ vulnerability. This attack type is detected with pattern:

::

.*(.*(http(s){0,1}|ftp(s){0,1}):).*

RFI emulation include two steps:

* Download file
   * Downloaded files are storing in the ``opt/tanner/scripts`` directory.
   * Create filename with ``hashlib.md5()`` from its content.
* Execute code from downloaded file with PHPox_ and return the result
   * Get script body from file
   * Connect to PHPox server (default 127.0.0.1:8088) and send script body
   * Get the result of execution in the response
   * Return the result


LFI emulator
~~~~~~~~~~~~
It emulates LFI_ vulnerability. This attack type is detected with pattern:

::

.*(\/\.\.)*(home|proc|usr|etc)\/.*

It is emualted using a docker container with Linux filesystem (default: ``busybox:latest``).

When LFI attack is detected, LFI emulator executes a command ``cat **file_to_be_read**`` within the docker and it returns the contents
of file if found else return ``No such file or directory``.

XSS emulator
~~~~~~~~~~~~
It emulates XSS_ vulnerability. This attack type is detected with pattern:

::

.*<(.|\n)*?>


Emulator returns the script body and the page, into which this script must be injected.

* Script body can be extracted from data in ``POST`` requests and from query in ``GET`` requests .
* To avoid replacing characters in data, we use ``urllib.parse.unquote`` function before analyzing path and post data with ``re``.
* Page is selected from the current session paths (see :doc:`sessions`). It's the last page with mime type ``text/html``.
* Script is injected into page on SNARE side.

SQLi emulator
~~~~~~~~~~~~~

It emulates `SQL injection`_ vulnerability. This attack is detected by ``libinjection``.

The emulator copies the original database (see :doc:`db_setup` for more info about db) to a dummy database for every attacker.
It uses UUID of the session for the attacker's db name. Every query is executed on the attacker's db.
The emulator returns the result of the execution and the page where SNARE should show the result.
It supports two types of DBs.
* **SQLITE**
  To enable it, set SQLI type to SQLITE in config
* **MySQL**
  To enable it, set SQLI type to MySQL in config and set other necessary fields - Host, User and Password

Command Execution Emulator
~~~~~~~~~~~~~~~~~~~~~~~~~~

It emulates `Command Execution`_ vulnerability. This attack is detected with pattern.

::

.*(alias|cat|cd|cp|echo|exec|find|for|grep|ifconfig|ls|man|mkdir|netstat|ping|ps|pwd|uname|wget|touch|while).*

* Each param value is checked against the pattern and ``command`` is extracted.
* The ``command`` is executed in a docker container safely.
* Results from container is injected into the index page.


.. _RFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Remote_File_Inclusion
.. _PHPox: https://github.com/mushorg/phpox
.. _LFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Local_File_Inclusion
.. _XSS: https://en.wikipedia.org/wiki/Cross-site_scripting
.. _SQL injection: https://en.wikipedia.org/wiki/SQL_injection
.. _Command Execution: https://www.owasp.org/index.php/Command_Injection
.. _manual: https://github.com/client9/libinjection/wiki/doc-sqli-python
