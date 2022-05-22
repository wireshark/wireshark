Lrexlib
=======

|  by Reuben Thomas (rrt@sc3d.org)
|  and Shmuel Zeigerman (shmuz@013net.net)

**Lrexlib** provides bindings of five regular expression library APIs
(POSIX_, PCRE_, PCRE2_, GNU_, TRE_ and Oniguruma_) to Lua_ >= 5.1.
The bindings for TRE and Oniguruma are not currently complete.

**Lrexlib** is copyright Reuben Thomas 2000-2020 and copyright Shmuel
Zeigerman 2004-2020, and is released under the same license as Lua,
the MIT_ license (otherwise known as the revised BSD license). There
is no warranty.

.. _POSIX: http://www.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap09.html
.. _PCRE: http://www.pcre.org/pcre.txt
.. _PCRE2: http://www.pcre.org/pcre2.txt
.. _GNU: ftp://ftp.gnu.org/old-gnu/regex/
.. _Oniguruma: https://github.com/kkos/oniguruma
.. _TRE: http://laurikari.net/tre/documentation/
.. _Lua: http://www.lua.org
.. _MIT: http://www.opensource.org/licenses/mit-license.php

Please report bugs and make suggestions to the maintainer, or use the
LuaForge trackers and mailing lists.

Thanks to Thatcher Ulrich for bug and warning fixes, and to Nick
Gammon for adding support for PCRE named subpatterns.

-----------------------------------------------------------

Installation
------------

Lrexlib is installed with LuaRocks_, using the command::

  luarocks install lrexlib-FLAVOUR

where **FLAVOUR** is one of PCRE, PCRE2, POSIX, oniguruma, TRE, GNU

.. _LuaRocks: http://www.luarocks.org


Links
-----

- License_
- `Reference Manual`_
- `LuaForge Project Page`_
- Download_

.. _License: http://rrthomas.github.com/lrexlib/license.html
.. _Reference Manual: http://rrthomas.github.com/lrexlib/manual.html
.. _LuaForge Project Page: http://luaforge.net/projects/lrexlib/
.. _Download: https://github.com/rrthomas/lrexlib/downloads
