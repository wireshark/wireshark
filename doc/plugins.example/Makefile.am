# Makefile.am
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
#

WARNFLAGS = -Wall -Wextra

plugindir := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --define-variable=libdir=$(libdir) --variable plugindir wireshark)

release_version := $(notdir $(plugindir))

plugin_LTLIBRARIES = hello.la

hello_la_SOURCES = hello.c

hello_la_CPPFLAGS = -DVERSION_RELEASE=\"$(release_version)\"

hello_la_CFLAGS = $(WIRESHARK_CFLAGS) -fvisibility=hidden $(WARNFLAGS)

hello_la_LDFLAGS = -module -avoid-version -shared

hello_la_LIBADD = $(WIRESHARK_LIBS)

homedir = $${HOME}/.local/lib/wireshark/plugins/$(release_version)

install-home:
	$(MKDIR_P) $(homedir) || exit 1; \
	$(INSTALL) $(builddir)/.libs/hello.so $(homedir)
