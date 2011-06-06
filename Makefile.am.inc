# Makefile.am.inc
# Include file for Makefile.am files to get additional rules
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

.l.c:
	$(RUNLEX) "$(LEX)" -o$@ $<

.def.sym:
	$(AWK) '/^EXPORTS$$/ {next;}; ${def_sym_filter_symbols} /^[^;]/ { print $$1;}' < $< > $@

# abi-compliance-checker descriptor
INCLUDE_DIRS = $(subst -I,NEWLINE,$(filter -I%, $(CFLAGS) -I$(abs_top_srcdir) -I$(abs_srcdir)))
abi-descriptor.xml: ../abi-descriptor.template
	sed "s|INCLUDE_DIRS|$(INCLUDE_DIRS)|g;s/NEWLINE/\n    /g" $< > $@
