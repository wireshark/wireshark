Lrexlib
=======

|  by Reuben Thomas (rrt@sc3d.org)
|  and Shmuel Zeigerman (shmuz@013net.net)

**Lrexlib** provides bindings of five regular expression library APIs
(POSIX_, PCRE_, GNU_, TRE_ and Oniguruma_) to Lua_ >= 5.1.
The bindings for TRE and Oniguruma are not currently complete.

**Lrexlib** is copyright Reuben Thomas 2000-2020 and copyright Shmuel
Zeigerman 2004-2020, and is released under the same license as Lua,
the MIT_ license (otherwise known as the revised BSD license). There
is no warranty.

.. _POSIX: https://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap09.html
.. _PCRE: https://www.pcre.org/current/doc/html/
.. _GNU: https://ftp.gnu.org/old-gnu/regex/
.. _Oniguruma: https://github.com/kkos/oniguruma
.. _TRE: https://laurikari.net/tre/documentation/
.. _Lua: https://www.lua.org
.. _MIT: https://www.opensource.org/licenses/mit-license.php

Please report bugs and make suggestions on GitHub_.

.. _GitHub: https://github.com/rrthomas/lrexlib/issues

Thanks to Thatcher Ulrich for bug and warning fixes, and to Nick
Gammon for adding support for PCRE named subpatterns.

-----------------------------------------------------------

Installation
------------

Lrexlib is installed with LuaRocks_, using the command::

  luarocks install lrexlib-FLAVOUR

where **FLAVOUR** is one of PCRE2, POSIX, oniguruma, TRE, GNU

Note that the obsolete PCRE version 1 is also supported, as flavour PCRE.

.. _LuaRocks: https://luarocks.org


Links
-----

- `GitHub project page`_
- License_
- `Reference Manual`_
- Downloads_

.. _GitHub project page: https://github.com/rrthomas/lrexlib
.. _License: https://rrthomas.github.io/lrexlib/license.html
.. _Reference Manual: https://rrthomas.github.io/lrexlib/manual.html
.. _Downloads: https://github.com/rrthomas/lrexlib/downloads
