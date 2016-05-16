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
lemon_builddir = $(top_builddir)/tools/lemon
LEMON = $(lemon_builddir)/lemon$(EXEEXT)
$(LEMON):
	cd $(lemon_builddir) && $(MAKE)

RUNLEX = $(top_srcdir)/tools/runlex.sh

INCLUDEDIRS = -I$(top_srcdir)

#AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS)

AM_CFLAGS = $(WERROR) $(WS_CFLAGS)

GENERATED_CFLAGS = $(WS_CFLAGS)

AM_CXXFLAGS = $(WERROR) $(WS_CXXFLAGS)

GENERATED_CXXFLAGS = $(WS_CXXFLAGS)

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

AM_V_LN_S = $(am__v_LN_S_@AM_V@)
am__v_LN_S_ = $(am__v_LN_S_@AM_DEFAULT_V@)
am__v_LN_S_0 = @echo "  LN_S    " $@;

# _PYTHON is a reserved automake keyword
AM_V_python = $(am__v_python_@AM_V@)
am__v_python_ = $(am__v_python_@AM_DEFAULT_V@)
am__v_python_0 = @echo "  PYTHON  " $@;

AM_V_YACC = $(am__v_YACC_@AM_V@)
am__v_YACC_ = $(am__v_YACC_@AM_DEFAULT_V@)
am__v_YACC_0 = @echo "  YACC    " $@;

.l.c:
	$(AM_V_RUNLEX)$(RUNLEX) "$(LEX)" "$(SED)" -o$@ $<

# abi-compliance-checker descriptor
abi_incdirs = $(subst -I,NEWLINE,$(filter -I%,$(WS_CFLAGS) -I$(abs_top_srcdir) -I$(abs_srcdir)))
abi_sysdirs = $(subst -isystem,NEWLINE,$(filter -isystem%,$(WS_CFLAGS)))
abi_includes = $(abi_incdirs) $(abi_sysdirs)
abi-descriptor.xml: ../abi-descriptor.template
	$(AM_V_SED)$(SED) \
		-e 's|@INCLUDE_DIRS@|$(abi_includes)|g' \
		-e 's/ *NEWLINE/\n    /g' \
		-e 's|@LIBRARY_OUTPUT_PATH@|{RELPATH}/.libs|' $< > $@
