# Makefile.am
# Automake file for Wireshark help files
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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

EXTRA_DIST = \
	$(help_DATA)		\
	$(srcdir)/faq.py	\
	faq.txt

CLEANFILES = faq.txt

MAINTAINERCLEANFILES = \
	Makefile.in

# Convert the FAQ to text.
faq.txt: $(srcdir)/faq.py
	$(AM_V_GEN)$(srcdir)/faq.py -b >$@.tmp && \
	$(srcdir)/../tools/html2text.py $@.tmp > $@ && \
	rm -f $@.tmp
