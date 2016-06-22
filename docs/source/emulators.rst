Emulators
---------
RFI emulator
~~~~~~~~~~~~
Emulate RFI_ vulnerability. This attack type is detected with pattern: 

::

.*(=.*(http(s){0,1}|ftp(s){0,1}):).*

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
Emulate LFI_ vulnerability. This attack type is detected with pattern: 

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



.. _RFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Remote_File_Inclusion
.. _PHPox: https://github.com/mushorg/phpox
.. _LFI: https://en.wikipedia.org/wiki/File_inclusion_vulnerability#Local_File_Inclusion