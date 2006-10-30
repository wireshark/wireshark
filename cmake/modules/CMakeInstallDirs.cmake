###################################################################
#
#  Copyright (c) 2006 Frederic Heem, <frederic.heem@telsey.it>
#  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# * Neither the name of the <ORGANIZATION> nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###################################################################
# - CMakeInstallDirs.cmake
# This script defines some variables that describe paths needed to install an application:
# CMAKE_INSTALL_BINDIR

# CMAKE_INSTALL_DATADIR
# CMAKE_INSTALL_SBINDIR
# CMAKE_INSTALL_SYSCONFDIR
# CMAKE_INSTALL_LOCALSTATEDIR
# CMAKE_INSTALL_LIBDIR
# CMAKE_INSTALL_MANDIR

#Documentation string
SET(CMAKE_INSTALL_BINDIR_DOC        "user executables [PREFIX/bin]")
SET(CMAKE_INSTALL_SBINDIR_DOC       "system admin executables [EPREFIX/sbin]")
SET(CMAKE_INSTALL_DATADIR_DOC       "read-only architecture-independent data [PREFIX/share]")
SET(CMAKE_INSTALL_SYSCONFDIR_DOC    "read-only single-machine data [PREFIX/etc]")
SET(CMAKE_INSTALL_LOCALSTATEDIR_DOC "modifiable single-machine data [PREFIX/var]")
SET(CMAKE_INSTALL_LIBDIR_DOC         "object code libraries [PREFIX/lib]")
SET(CMAKE_INSTALL_MANDIR_DOC        "man documentation [PREFIX/man]")

#Special case for /etc and /var when prefix is /usr
IF(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr")
  SET(CMAKE_INSTALL_SYSCONFDIR "/etc" CACHE PATH ${CMAKE_INSTALL_SYSCONFDIR_DOC})
  SET(CMAKE_INSTALL_LOCALSTATEDIR "/var" CACHE PATH ${CMAKE_INSTALL_LOCALSTATEDIR_DOC})
ENDIF(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr")

#General case
SET(CMAKE_INSTALL_BINDIR "${CMAKE_INSTALL_PREFIX}/bin"
    CACHE PATH ${CMAKE_INSTALL_BINDIR_DOC})
SET(CMAKE_INSTALL_SBINDIR "${CMAKE_INSTALL_PREFIX}/sbin"
    CACHE PATH ${CMAKE_INSTALL_SBINDIR_DOC})
SET(CMAKE_INSTALL_DATADIR "${CMAKE_INSTALL_PREFIX}/share"
    CACHE PATH ${CMAKE_INSTALL_DATADIR_DOC})
SET(CMAKE_INSTALL_SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc"
    CACHE PATH ${CMAKE_INSTALL_SYSCONFDIR_DOC})
SET(CMAKE_INSTALL_LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var"
    CACHE PATH ${CMAKE_INSTALL_LOCALSTATEDIR_DOC})
SET(CMAKE_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib"
    CACHE PATH ${CMAKE_INSTALL_LIBDIR_DOC})
SET(CMAKE_INSTALL_MANDIR "${CMAKE_INSTALL_PREFIX}/man"
    CACHE PATH ${CMAKE_INSTALL_MANDIR_DOC})


MARK_AS_ADVANCED(
  CMAKE_INSTALL_BINDIR
  CMAKE_INSTALL_SBINDIR
  CMAKE_INSTALL_DATADIR
  CMAKE_INSTALL_SYSCONFDIR
  CMAKE_INSTALL_LOCALSTATEDIR
  CMAKE_INSTALL_LIBDIR
  CMAKE_INSTALL_MANDIR
)




