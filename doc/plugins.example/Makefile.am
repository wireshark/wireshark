# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

WARNFLAGS = -Wall -Wextra

plugindir := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --define-variable=libdir=$(libdir) --variable plugindir wireshark)

epan_plugindir = $(plugindir)/epan

VERSION_RELEASE := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --variable VERSION_RELEASE wireshark)

epan_plugin_LTLIBRARIES = hello.la

hello_la_SOURCES = hello.c

hello_la_CPPFLAGS = -DVERSION_RELEASE=\"$(VERSION_RELEASE)\"

hello_la_CFLAGS = $(WIRESHARK_CFLAGS) -fvisibility=hidden $(WARNFLAGS)

hello_la_LDFLAGS = -module -avoid-version -shared

hello_la_LIBADD = $(WIRESHARK_LIBS)

homedir = $${HOME}/.local/lib/wireshark/plugins/$(VERSION_RELEASE)/epan

install-home:
	$(MKDIR_P) $(homedir) || exit 1; \
	$(INSTALL) $(builddir)/.libs/hello.so $(homedir)
