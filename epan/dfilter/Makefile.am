# Makefile.am
#
# $Id: Makefile.am,v 1.7 2001/02/27 19:23:28 gram Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 2001 Gerald Combs
#
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

# We produce an archive library. In the future, when libethereal is a
# shared library, this will be linked into libethereal. While libethereal
# is an archive library, any executable linking against libethereal will
# also need to link against libftypes.
noinst_LIBRARIES = libdfilter.a

CLEANFILES = \
	libdfilter.a		\
	*~

INCLUDES = -I$(srcdir)/../..  -I$(srcdir)/$(LEMON)

libdfilter_a_SOURCES = \
	cppmagic.h		\
	dfilter.c		\
	dfilter.h		\
	dfilter-int.h		\
	dfvm.c			\
	dfvm.h			\
	drange.c		\
	drange.h		\
	gencode.c		\
	gencode.h		\
	glib-util.c		\
	glib-util.h		\
	grammar.c		\
	grammar.h		\
	scanner.c		\
	semcheck.c		\
	semcheck.h		\
	sttype-integer.c	\
	sttype-pointer.c	\
	sttype-range.c		\
	sttype-range.h		\
	sttype-string.c		\
	sttype-test.c		\
	sttype-test.h		\
	syntax-tree.c		\
	syntax-tree.h

EXTRA_DIST = \
	grammar.lemon		\
	scanner.l		\
	Makefile.nmake		

scanner.c : scanner.l
	$(LEX) -Pdf_ -oscanner.c $(srcdir)/scanner.l

scanner.o : scanner.c grammar.h

LEMON=../../tools/lemon

grammar.h : grammar.c
grammar.c : grammar.lemon
	$(LEMON)/lemon t=$(srcdir)/$(LEMON)/lempar.c $(srcdir)/grammar.lemon || \
		(rm -f grammar.c grammar.h ; false)

