# Makefile.am
# Automake file for Wiretap
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

ACLOCAL_AMFLAGS = `../aclocal-flags`

include Makefile.common

lib_LTLIBRARIES = libwiretap.la
libwiretap_la_LDFLAGS = -version-info 0:1:0 @SHAREDLIB_LDFLAGS@

CLEANFILES = \
	libwiretap.a		\
	libwiretap.la		\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in		\
	aclocal.m4		\
	config.h.in		\
	configure

libwiretap_la_SOURCES = \
	$(NONGENERATED_C_FILES)	\
	$(GENERATOR_SOURCES)	\
	$(NONGENERATED_HEADER_FILES)

EXTRA_DIST = \
	README.developer	\
	config.h.win32		\
	Makefile.common		\
	Makefile.nmake		\
	wtap.def		\
	$(GENERATED_FILES)

# Any POSIX-compatible YACC should honor the -p flag
AM_YFLAGS=-d -p ascend

ascend-scanner.c : ascend-scanner.l
	@if [ ! -x "$(LEX)" ]; then \
		echo "Neither lex nor flex was found"; \
		exit 1; \
	fi
	$(LEX) -Pascend -oascend-scanner.c $(srcdir)/ascend-scanner.l
