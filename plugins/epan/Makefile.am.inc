# Makefile.am.inc
# Include file with common automake definitions for dissector plugins
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/plugins/Makefile.am.inc

#
# Build plugin.c, which contains the plugin_version[] and plugin_release[]
# string, and a function plugin_register() that calls the register routines
# for all protocols.
#
# We do this by scanning sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions:  The name of the proto_register_* routines and
# proto_reg_handoff_* routines must start in column zero, or must be
# preceded only by "void " starting in column zero, and must not be
# inside #if.
#
# REGISTER_SRC_FILES is assumed to have all the files that need to be scanned.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the files doesn't work with some "make"s; they seem to
# pass only the first few names in the list to the shell, for some
# reason.
#
# Therefore, we use a script to generate the register.c file.
# The first argument is the directory in which the source files live.
# The second argument is "plugin", to indicate that we should build
# a plugin.c file for a dissector plugin.
# All subsequent arguments are the files to scan.
#
plugin.c: $(REGISTER_SRC_FILES) $(top_srcdir)/tools/make-plugin-reg.py
	@echo Making plugin.c
	@$(PYTHON) $(top_srcdir)/tools/make-plugin-reg.py $(srcdir) \
		plugin $(REGISTER_SRC_FILES)
