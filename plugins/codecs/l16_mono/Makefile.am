# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/codecs/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = l16mono

PLUGIN_VERSION = 0.1.0

BUILT_SOURCES = \
	plugin.c

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	l16decode.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

wiretap_plugin_LTLIBRARIES = l16mono.la

l16mono_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

nodist_l16mono_la_SOURCES = \
	plugin.c

l16mono_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS) -I$(abs_top_srcdir)/codecs

l16mono_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS) -I$(abs_top_srcdir)/codecs

l16mono_la_LDFLAGS = $(PLUGIN_LDFLAGS)

DISTCLEANFILES = \
	plugin.c

EXTRA_DIST = \
	CMakeLists.txt
