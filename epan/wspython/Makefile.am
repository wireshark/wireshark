# Makefile.am
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

include Makefile.common

noinst_LTLIBRARIES = libwspython.la

CLEANFILES = \
	libwspython.a	\
	libwspython.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

INCLUDES = -I$(srcdir)/../.. -I$(srcdir)/..

libwspython_la_SOURCES = $(LIBWSPYTHON_SRC) $(LIBWSPYTHON_INCLUDES)

libwspython_la_LIBADD = @PY_LIBS@
libwspython_la_CFLAGS = @PY_CFLAGS@

wspythondir = @pythondir@

wspython_DATA =	\
	register-dissector.py			\
	wspy_dissector.py			\
	wspy_dissectors/homeplug.py.sample	\
	wspy_libws.py


EXTRA_DIST = \
	Makefile.common				\
	Makefile.nmake				\
	$(wspython_DATA)			\
	CMakeLists.txt

