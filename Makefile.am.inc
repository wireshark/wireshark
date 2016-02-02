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

lemon_srcdir = $(top_srcdir)/tools/lemon

LEMON = $(top_builddir)/tools/lemon/lemon$(EXEEXT)

RUNLEX = $(top_srcdir)/tools/runlex.sh

AM_CPPFLAGS = $(WS_CPPFLAGS) -I$(top_srcdir) -DTOP_SRCDIR=\"$(abs_top_srcdir)\"

AM_CFLAGS = $(WS_CFLAGS)

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS += -Werror
endif

GENERATED_CFLAGS = $(WS_CFLAGS)

AM_CXXFLAGS = $(WS_CXXFLAGS)

if HAVE_WARNINGS_AS_ERRORS
AM_CXXFLAGS += -Werror
endif

AM_LDFLAGS = $(WS_LDFLAGS)

AM_V_PERL = $(am__v_PERL_@AM_V@)
am__v_PERL_ = $(am__v_PERL_@AM_DEFAULT_V@)
am__v_PERL_0 = @echo "  PERL    " $@;

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
abi_incdirs = $(subst -I,NEWLINE,$(filter -I%,$(WS_CFLAGS) -I$(abs_top_srcdir) -I$(abs_srcdir)))
abi_sysdirs = $(subst -isystem,NEWLINE,$(filter -isystem%,$(WS_CFLAGS)))
INCLUDE_DIRS = $(abi_incdirs) $(abi_sysdirs)
abi-descriptor.xml: ../abi-descriptor.template
	$(AM_V_SED)$(SED) \
		-e 's|@INCLUDE_DIRS@|$(INCLUDE_DIRS)|g' \
		-e 's/ *NEWLINE/\n    /g' \
		-e 's|@LIBRARY_OUTPUT_PATH@|{RELPATH}/.libs|' $< > $@
