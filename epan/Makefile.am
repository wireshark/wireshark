# Makefile.am
# Automake file for the EPAN library
# (Ethereal Protocol ANalyzer Library)
#
# $Id: Makefile.am,v 1.15 2001/01/17 06:13:39 guy Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 1998 Gerald Combs
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


# Any POSIX-compatible YACC should honor the -p flag
YFLAGS=-d -p dfilter_

# EPAN will eventually be a shared library. While I move source code around,
# however, it is an archive library.

ACLOCAL_AMFLAGS = `../aclocal-flags`

noinst_LIBRARIES = libethereal.a

INCLUDES = -I$(srcdir)/..

libethereal_a_SOURCES = \
	bitswap.c		\
	bitswap.h		\
	conversation.c		\
	conversation.h		\
	dfilter-int.h		\
	dfilter-grammar.y	\
	dfilter-scanner.l	\
	dfilter.c		\
	dfilter.h		\
	epan.c			\
	epan.h			\
	except.c		\
	except.h		\
	exceptions.h		\
	filesystem.c		\
	filesystem.h		\
	ipv4.c			\
	ipv4.h			\
	packet.c		\
	packet.h		\
	pint.h			\
	plugins.c		\
	plugins.h		\
	proto.c			\
	proto.h			\
	resolv.c		\
	resolv.h		\
	strutil.c		\
	strutil.h		\
	tvbuff.c		\
	tvbuff.h

EXTRA_libethereal_a_SOURCES =	\
        inet_aton.c		\
	inet_pton.c		\
	inet_ntop.c		\
	inet_aton.h		\
	inet_v6defs.h

EXTRA_DIST = \
	config.h.win32		\
	dfilter-grammar.c	\
	dfilter-grammar.h	\
	dfilter-scanner.c	\
	Makefile.nmake		\
	tvbtest.c

CLEANFILES = \
	libethereal.a	\
	*~

#
# Add the object files for missing routines, if any.
#
libethereal_a_LIBADD = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@
libethereal_a_DEPENDENCIES = @INET_ATON_O@ @INET_PTON_O@ @INET_NTOP_O@

dfilter-scanner.c : dfilter-scanner.l
	$(LEX) -Pdfilter_ -odfilter-scanner.c $(srcdir)/dfilter-scanner.l

tvbtest: tvbtest.o tvbuff.o except.o strutil.o
	$(LINK) -o tvbtest tvbtest.o tvbuff.o except.o strutil.o `glib-config --libs`
