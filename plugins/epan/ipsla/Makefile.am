include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/epan/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = ipsla

PLUGIN_VERSION = 1.0.0

BUILT_SOURCES = \
	plugin.c

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-ipsla.c \

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES =

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

epan_plugin_LTLIBRARIES = ipsla.la

ipsla_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

nodist_ipsla_la_SOURCES = \
	plugin.c

ipsla_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

ipsla_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

ipsla_la_LDFLAGS = $(PLUGIN_LDFLAGS)

DISTCLEANFILES = \
	plugin.c

EXTRA_DIST = \
	CMakeLists.txt
