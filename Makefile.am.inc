# Makefile.am.inc
# Include file for Makefile.am files to get additional rules
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

AUTOMAKE_OPTIONS = -Wno-portability

AM_V_AWK = $(am__v_AWK_@AM_V@)
am__v_AWK_ = $(am__v_AWK_@AM_DEFAULT_V@)
am__v_AWK_0 = @echo "  AWK     " $@;

AM_V_LEMON = $(am__v_LEMON_@AM_V@)
am__v_LEMON_ = $(am__v_LEMON_@AM_DEFAULT_V@)
am__v_LEMON_0 = @echo "  LEMON   " $@;

AM_V_RUNLEX = $(am__v_RUNLEX_@AM_V@)
am__v_RUNLEX_ = $(am__v_RUNLEX_@AM_DEFAULT_V@)
am__v_RUNLEX_0 = @echo "  RUNLEX  " $@;

AM_V_SED = $(am__v_SED_@AM_V@)
am__v_SED_ = $(am__v_SED_@AM_DEFAULT_V@)
am__v_SED_0 = @echo "  SED     " $@;

.l.c:
	$(AM_V_RUNLEX)$(RUNLEX) "$(LEX)" "$(SED)" -o$@ $<

.def.sym:
	$(AM_V_AWK)$(AWK) '/^EXPORTS$$/ {next;}; ${def_sym_filter_symbols} /^[^;]/ { print $$1;}' < $< > $@

# abi-compliance-checker descriptor
INCLUDE_DIRS = $(subst -I,NEWLINE,$(filter -I%, $(CFLAGS) -I$(abs_top_srcdir) -I$(abs_srcdir)))
abi-descriptor.xml: ../abi-descriptor.template
	$(AM_V_SED)sed "s|@INCLUDE_DIRS@|$(INCLUDE_DIRS)|g;s/NEWLINE/\n    /g;s|@LIBRARY_OUTPUT_PATH@|{RELPATH}/.libs|" $< > $@
