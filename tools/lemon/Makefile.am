# Makefile.am
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2001 Gerald Combs
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

# We produce an archive library. In the future, when libwireshark is a
# shared library, this will be linked into libwireshark. While libwireshark
# is an archive library, any executable linking against libwireshark will
# also need to link against libftypes.

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

noinst_PROGRAMS = lemon

CLEANFILES = \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

lemon$(EXEEXT): lemon.c
	$(CC_FOR_BUILD) -I$(top_builddir) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@ $?

EXTRA_DIST = \
	cppmagic.h		\
	lemon.html		\
	lemonflex-head.inc	\
	lemonflex-tail.inc	\
	lempar.c		\
	Makefile.nmake		\
	README			\
	CMakeLists.txt

