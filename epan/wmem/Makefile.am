# Makefile.am
# Automake file for Wireshark Memory Manager
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

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

include Makefile.common

AM_CPPFLAGS = $(LIBWMEM_CFLAGS)

noinst_LTLIBRARIES = libwmem.la

CLEANFILES = \
	libwmem.a	\
	libwmem.la	\
	*~

DISTCLEANFILES =

MAINTAINERCLEANFILES =	\
	Makefile.in

INCLUDES = -I$(top_srcdir)

libwmem_la_SOURCES =	\
	$(LIBWMEM_SRC)	\
	$(LIBWMEM_INCLUDES)

EXTRA_DIST = \
	Makefile.common	\
	Makefile.nmake

checkapi:
	$(PERL) ../../tools/checkAPIs.pl -g termoutput -build \
	$(LIBWMEM_SRC)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
