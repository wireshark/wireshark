# Makefile.am
# Automake file for the GTK interface routines for Ethereal
#
# $Id: Makefile.am,v 1.89 2004/01/22 20:31:44 guy Exp $
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

noinst_HEADERS = \
	capture_combo_utils.h \
	capture_dlg.h	\
	capture_prefs.h	\
	color_dlg.h	\
	color_filters.h	\
	color_utils.h	\
	colors.h	\
	column_prefs.h	\
	compat_macros.h	\
	decode_as_dlg.h	\
	dfilter_expr_dlg.h \
	dlg_utils.h	\
	endpoint_talkers_table.h \
	file_dlg.h	\
	filter_prefs.h	\
	find_dlg.h	\
	follow_dlg.h	\
	goto_dlg.h	\
	gtkglobals.h	\
	gtk_stat_util.h \
	gui_prefs.h	\
	help_dlg.h	\
	keys.h		\
	main.h		\
	menu.h		\
	nameres_prefs.h	\
	packet_list.h	\
	packet_win.h	\
	prefs_dlg.h	\
	print_prefs.h	\
	proto_dlg.h	\
	proto_draw.h	\
	proto_hier_stats_dlg.h	\
	recent.h	\
	rtp_analysis.h	\
	rtp_stream.h	\
	rtp_stream_dlg.h \
	service_response_time_table.h	\
	stream_prefs.h	\
	summary_dlg.h   \
	supported_protos_dlg.h   \
	tap_dfilter_dlg.h \
	tcp_graph.h     \
	toolbar.h       \
	ui_util.h

if USE_GTK2
libui_a_SOURCES = \
	$(ETHEREAL_GTK_SRC) \
	$(noinst_HEADERS) \
	$(ETHEREAL_TAP_SRC)
else
libui_a_SOURCES = \
	ethclist.c	\
	ethclist.h	\
	$(ETHEREAL_GTK_SRC) \
	$(noinst_HEADERS) \
	$(ETHEREAL_TAP_SRC)
endif

EXTRA_DIST = \
	Makefile.nmake \
	print_mswin.c  \
	print_mswin.h

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap
