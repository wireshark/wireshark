# Makefile.am
# Automake file for the GTK interface routines for Ethereal
#
# $Id: Makefile.am,v 1.88 2004/01/22 18:08:58 ulfl Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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

include Makefile.common

noinst_LIBRARIES = libui.a

CLEANFILES = \
	libui.a		\
	*~

ethereal-tap-register.c: $(ETHEREAL_TAP_SRC) $(top_srcdir)/make-tapreg-dotc
	@echo Making ethereal-tap-register.c
	@$(top_srcdir)/make-tapreg-dotc ethereal-tap-register.c $(srcdir) $(ETHEREAL_TAP_SRC)

if USE_GTK2
libui_a_SOURCES = \
	$(ETHEREAL_GTK_SRC) \
	$(noinst_GTK_HEADERS) \
	$(ETHEREAL_TAP_SRC)
else
libui_a_SOURCES = \
	ethclist.c	\
	ethclist.h	\
	$(ETHEREAL_GTK_SRC) \
	$(noinst_GTK_HEADERS) \
	$(ETHEREAL_TAP_SRC)
endif

EXTRA_DIST = \
	Makefile.nmake \
	print_mswin.c  \
	print_mswin.h

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap
