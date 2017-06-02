Emulators
---------
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

During initialization LFI emulator creates the virtualdocs environment in ``/opt/tanner/virtualdocs`` folder from ``vdocs.json``, which in  ``data`` folder of the project.

Linux system files are stored in subdirectory ``linux``

This json has next structure:

.. code-block:: javascript

    {
        "directory/filename":"content"
    }


For example, if we want to add passwd file into the virtualdocs, we should add JSON object into ``vdocs.json``:

.. code-block:: javascript

    {
        "etc/passwd":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n<...>"
    }

When LFI attack is detected, LFI emulator:

* Get available files from the ``linux`` directory
* Extract the ``filename`` from requested path
* Looking for the ``filename`` in available files
* If the ``filename`` was found, return the content of the file


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

It emulates `SQL injection`_ vulnerability. This attack is detected by ``libinjection``. To install ``libinjection``, see the official manual_.

The emulator copies the original database (see :doc:`db_setup` for more info about db) to a dummy database for every attacker.
It uses UUID of the session for the attacker's db name. Every query is executed on the attacker's db.
The emulator returns the result of the execution and the page where SNARE should show the result.

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