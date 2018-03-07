# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

bin_PROGRAMS = idl2wrs

idl2wrs_SOURCES = idl2wrs.c

idl2wrs_LDADD = $(GLIB_LIBS) ../../../wsutil/libwsutil.la

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
