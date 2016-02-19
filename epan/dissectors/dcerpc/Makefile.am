# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
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

EXTRA_DIST = \
	CMakeLists.txt				\
	Makefile.inc				\
	idl2wrs.c				\
	budb/Makefile				\
	budb/budb.cnf				\
	budb/budb.idl				\
	budb/packet-dcerpc-budb-template.c	\
	budb/packet-dcerpc-budb-template.h	\
	butc/Makefile				\
	butc/butc.cnf				\
	butc/butc.idl				\
	butc/packet-dcerpc-butc-template.c	\
	butc/packet-dcerpc-butc-template.h	\
	drsuapi/Makefile			\
	drsuapi/drsuapi.cnf			\
	drsuapi/drsuapi.idl			\
	drsuapi/packet-dcerpc-drsuapi-template.c \
	drsuapi/packet-dcerpc-drsuapi-template.h

MAINTAINERCLEANFILES =  \
	Makefile.in

bin_PROGRAMS = idl2wrs

idl2wrs_SOURCES = idl2wrs.c

idl2wrs_LDADD = $(GLIB_LIBS)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 4
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=4 tabstop=4 noexpandtab:
# :indentSize=4:tabSize=4:noTabs=false:
#
