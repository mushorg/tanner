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

PHP Code Injection Emulator
~~~~~~~~~~~~~~~~~~~~~~~~~~~
It emulates `PHP code injection`_ vuln. Usually, this type of vuln is found where user input is directly passed to
functions like eval, assert. To mimic the functionality, user input is converted to the following code
``<?php eval('$a = user_input'); ?>`` and then passed to phpox to get php code emulation results.

PHP Object Injection Emulator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
It emulates `PHP object injection`_ vuln. PHP allows object serialization So, this type of vulnerability occurs when not
properly sanitized input is passed to ``unserialize()`` PHP function. Exploiting this vulnerability involves Magic methods like
``__construct and __destruct`` which are called automatically when an object is created or destroyed and methods like
``__sleep and __wakeup`` are called when an object is serialized or unserialized. The input serialized object is
detected with regex pattern.

::

(^|;|{|})O:[0-9]+:

To mimic this functionality the user input is injected to a vulnerable custom class with magic methods and then it
is passed to php sandbox to get the injection results.

**Important Note:** You will need to expose the vulnerable code to the attacker using your own suitable method. The
default vulnerable code is `here`_. But you can always add your own custom class if needed.

CRLF Emulator
~~~~~~~~~~~~~
It emulates `CRLF`_ vuln. The attack is detected using ``\r\n`` pattern in the input. The parameter which looks suspicious
is injected as a header with parameter name as header name and param value as header value.

XXE Injection Emulator
~~~~~~~~~~~~~~~~~~~~~~
It emulates `External Entity Injection`_ vulnerability. This type of vulnerability occurs when XML input with reference
to an external entity is parsed by a weakly configured parser. It is exploited by putting specially crafted DTDs with malicious
entities defined in it. The XML input is detected by regex pattern.

::

.*<(\?xml|(!DOCTYPE.*)).*>

To mimic this functionality attacker's input will be injected into a vulnerable PHP code which parses the XML data
and then it gets the injection results from php sandbox.

**Note:** You can customize the vulnerable PHP code and can make it more intuitive. for eg: emulating a submit form with user, password fields.

Template Injection Emulator
~~~~~~~~~~~~~~~~~~~~~~~~~~~
This emulates `Template Injection`_ vulnerability. This is exploited by using specially crafted payloads for different template engines.
For now we are covering ``tornado`` and ``mako`` python templating engines. The injection formats are different for every engine
for ex ``tornado: {{7*7}} -> 49`` and ``mako: <% x=7*7 %>${x} -> 49``.

The payload is detected using regex pattern:

::

.*({{.*}}).* - Tornado
.*(<%.*|\s%>).* - Mako

To mimic this functionality vulnerable template renderers are stored in `files/engines` directory for every engine in which the payload will be injected.
These vulnerable templates are executed safely using custom docker image to get the injection results.


.. _Template Injection: https://portswigger.net/blog/server-side-template-injection
.. _RFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Remote_File_Inclusion
.. _PHPox: https://github.com/mushorg/phpox
.. _LFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Local_File_Inclusion
.. _XSS: https://en.wikipedia.org/wiki/Cross-site_scripting
.. _SQL injection: https://en.wikipedia.org/wiki/SQL_injection
.. _Command Execution: https://www.owasp.org/index.php/Command_Injection
.. _PHP Code Injection: https://www.owasp.org/index.php/Code_Injection
.. _PHP object injection: https://www.owasp.org/index.php/PHP_Object_Injection
.. _CRLF: https://www.owasp.org/index.php/CRLF_Injection
.. _External Entity Injection: https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
.. _manual: https://github.com/client9/libinjection/wiki/doc-sqli-python
.. _here: https://github.com/mushorg/tanner/blob/8ce13d1f7d4423ddaf0e7910781199be9b90ce40/tanner/emulators/php_object_injection.py#L16
