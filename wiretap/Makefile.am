# Makefile.am
# Automake file for Wiretap
#
# $Id: Makefile.am,v 1.43 2003/08/22 19:07:44 guy Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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

noinst_LIBRARIES = libwiretap.a

#EXTRA_LIBRARIES = libwiretap.a

CLEANFILES = \
	libwiretap.a		\
	*~

libwiretap_a_SOURCES = \
	ascend-grammar.y	\
	ascend-scanner.l	\
	ascend.c		\
	ascend.h		\
	ascend-int.h		\
	atm.c			\
	atm.h			\
	buffer.c		\
	buffer.h		\
	cosine.h		\
	cosine.c		\
	csids.c			\
	csids.h			\
	dbs-etherwatch.c	\
	dbs-etherwatch.h	\
	etherpeek.c             \
	etherpeek.h             \
	file_io.c		\
	file_wrappers.c		\
	file_wrappers.h		\
	i4btrace.c		\
	i4btrace.h		\
	i4b_trace.h		\
	iptrace.c		\
	iptrace.h		\
	lanalyzer.c		\
	lanalyzer.h		\
	libpcap.c		\
	libpcap.h		\
	netmon.c		\
	netmon.h		\
	nettl.c			\
	nettl.h			\
	netxray.c		\
	netxray.h		\
	ngsniffer.c		\
	ngsniffer.h		\
	pppdump.c		\
	pppdump.h		\
	radcom.c		\
	radcom.h		\
	snoop.c			\
	snoop.h			\
	toshiba.c		\
	toshiba.h		\
	visual.c		\
	visual.h		\
	vms.c			\
	vms.h			\
	wtap.c			\
	wtap.h			\
	wtap-capture.h		\
	wtap-int.h		\
	5views.c		\
	5views.h

EXTRA_DIST = \
	README.developer	\
	ascend-grammar.c	\
	ascend-grammar.h	\
	ascend-scanner.c	\
	config.h.win32		\
	Makefile.nmake		\
	wtap.def

# Any POSIX-compatible YACC should honor the -p flag
AM_YFLAGS=-d -p ascend

ascend-scanner.c : ascend-scanner.l
	$(LEX) -Pascend -oascend-scanner.c $(srcdir)/ascend-scanner.l
