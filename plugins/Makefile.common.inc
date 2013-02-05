#
# Common definitions for plugin Makefile.common files
#
# $Id$
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
# Source files are divided up along several axes:
#
# C vs. C++ - this is used on Windows to generated lists of object files
# with .c=.obj or .cpp=.obj
#
# Dissector vs. non-dissector - dissector files are scanned for
# registration functions, non-dissector files aren't.
#
# Generated and distributed, generated and not distributed, and not
# generated - "make maintainer-clean" on UN*X and "nmake distclean"
# on Windows remove all generated files, "make distclean" on UN*X
# removes all not-distributed generated files, and non-distributed
# generated files aren't put into the distribution.
#

#
# All distributed generated dissector source files.
#
GENERATED_DISSECTOR_SRC_FILES = \
	$(GENERATED_DISSECTOR_C_FILES) \
	$(GENERATED_DISSECTOR_CPP_FILES)

#
# All distributed generated non-dissector source files.
#
GENERATED_SUPPORT_SRC_FILES = \
	$(GENERATED_SUPPORT_C_FILES) \
	$(GENERATED_SUPPORT_CPP_FILES)

#
# All distributed generated source files.
#
GENERATED_SRC_FILES = \
	$(GENERATED_DISSECTOR_SRC_FILES) \
	$(GENERATED_SUPPORT_SRC_FILES)

#
# All non-distributed generated dissector source files.
#
NODIST_GENERATED_DISSECTOR_SRC_FILES = \
	$(NODIST_GENERATED_DISSECTOR_C_FILES) \
	$(NODIST_GENERATED_DISSECTOR_CPP_FILES)

#
# All non-distributed generated non-dissector source files.
#
NODIST_GENERATED_SUPPORT_SRC_FILES = \
	$(NODIST_GENERATED_SUPPORT_C_FILES) \
	$(NODIST_GENERATED_SUPPORT_CPP_FILES)

#
# All non-distributed generated source files.
#
NODIST_GENERATED_SRC_FILES = \
	$(NODIST_GENERATED_DISSECTOR_SRC_FILES) \
	$(NODIST_GENERATED_SUPPORT_SRC_FILES)

#
# All distributed dissector source files.
#
DISSECTOR_SRC_FILES = \
	$(DISSECTOR_C_FILES) \
	$(DISSECTOR_CPP_FILES)

#
# All distributed non-dissector source files.
#
SUPPORT_SRC_FILES = \
	$(SUPPORT_C_FILES) \
	$(SUPPORT_CPP_FILES)

#
# All non-distributed non-dissector source files.
#
NODIST_SUPPORT_SRC_FILES = \
	$(NODIST_SUPPORT_C_FILES) \
	$(NODIST_SUPPORT_CPP_FILES)

#
# All distributed source files.
#
SRC_FILES = \
	$(DISSECTOR_SRC_FILES) \
	$(SUPPORT_SRC_FILES)

#
# All non-distributed source files.
#
NODIST_SRC_FILES = \
	$(NODIST_DISSECTOR_SRC_FILES) \
	$(NODIST_SUPPORT_SRC_FILES)
