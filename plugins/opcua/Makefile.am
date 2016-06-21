# Makefile.am
#
# Adapted by Gerhard Gappmeier for OpcUa
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
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = opcua

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	opcua.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES) \
	opcua_transport_layer.c \
	opcua_security_layer.c \
	opcua_application_layer.c \
	opcua_serviceparser.c \
	opcua_complextypeparser.c \
	opcua_enumparser.c \
	opcua_simpletypes.c \
	opcua_servicetable.c \
	opcua_extensionobjecttable.c \
	opcua_hfindeces.c \
	opcua_statuscode.c

# Headers.
CLEAN_HEADER_FILES = \
	opcua_complextypeparser.h \
	opcua_enumparser.h \
	opcua_hfindeces.h \
	opcua_statuscode.h \
	opcua_identifiers.h \
	opcua_serviceparser.h \
	opcua_simpletypes.h \
	opcua_servicetable.h \
	opcua_application_layer.h \
	opcua_security_layer.h \
	opcua_transport_layer.h \
	opcua_extensionobjectids.h \
	opcua_serviceids.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = opcua.la

opcua_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

opcua_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

opcua_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

opcua_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	opcua \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	README			\
	CMakeLists.txt
