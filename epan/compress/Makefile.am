# Makefile.am
# Automake file for the compress for Wireshark
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include Makefile.common

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)

noinst_LTLIBRARIES = liblzxpress.la

CLEANFILES = \
	liblzxpress.a	\
	liblzxpress.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES =	\
	Makefile.in

liblzxpress_la_SOURCES =	\
	$(LIBLZXPRESS_SRC)	\
	$(LIBLZXPRESS_INCLUDES)

EXTRA_DIST = \
	Makefile.common	\
	Makefile.nmake

checkapi:
	$(PERL) ../../tools/checkAPIs.pl -g termoutput -build \
	$(LIBLZXPRESS_SRC)
