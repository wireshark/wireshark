# Makefile.am
# Automake file for Ethereal help files
#
# $Id: Makefile.am,v 1.1 2003/12/13 18:05:49 gerald Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
# Copyright 2003 Gerald Combs
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

SUFFIXES = .txt .h
.txt.h: $(@@:.h=.txt)
	@ echo making $@
	@ rm -f $@
	$(SHELL) convert-include.sh $*


BUILT_SOURCES = \
	capture_filters.h \
	display_filters.h \
	faq.h             \
	overview.h        \
	well_known.h


helpfile_SOURCES =            \
	capture_filters.txt \
	display_filters.txt \
	faq.txt             \
	overview.txt        \
	well_known.txt

EXTRA_DIST = $(BUILT_SOURCES) $(helpfile_SOURCES) convert-include.sh Makefile.nmake

CLEANFILES = $(BUILT_SOURCES)
