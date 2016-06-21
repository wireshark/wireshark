# Makefile.am
# Automake file for the "random packet generator" routines for Wireshark
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS)

noinst_LIBRARIES = librandpkt_core.a

CLEANFILES = \
	doxygen-randpkt_core.tag	\
	librandpkt_core.a		\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

# All sources that should be put in the source distribution tarball
librandpkt_core_a_SOURCES = \
	randpkt_core.c	\
	randpkt_core.h

librandpkt_core_a_DEPENDENCIES =

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(librandpkt_core_a_SOURCES)

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir) \
	$(librandpkt_core_a_SOURCES)

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	CMakeLists.txt			\
	doxygen.cfg.in
