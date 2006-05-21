# Makefile.am
# Automake file for Ethereal help files
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
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

#
# Install the help files in the "help" subdirectory of the data directory.
#
helpdir = $(pkgdatadir)/help
help_DATA = \
	toc			\
	getting_started.txt	\
	capturing.txt		\
	capture_filters.txt	\
	display_filters.txt	\
	faq.txt			\
	overview.txt

EXTRA_DIST = $(help_DATA) Makefile.nmake

CLEANFILES = 

MAINTAINERCLEANFILES = \
	Makefile.in

