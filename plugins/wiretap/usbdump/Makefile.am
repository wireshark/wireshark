# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/wiretap/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = usbdump

PLUGIN_VERSION = 0.0.1

BUILT_SOURCES = \
	plugin.c

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	usbdump.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

wiretap_plugin_LTLIBRARIES = usbdump.la

usbdump_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

nodist_usbdump_la_SOURCES = \
	plugin.c

usbdump_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS) -I$(abs_top_srcdir)/wiretap

usbdump_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS) -I$(abs_top_srcdir)/wiretap

usbdump_la_LDFLAGS = $(PLUGIN_LDFLAGS)

DISTCLEANFILES = \
	plugin.c

EXTRA_DIST = \
	CMakeLists.txt
