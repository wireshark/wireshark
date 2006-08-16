# Makefile.am
# Automake file for the GTK interface routines for Wireshark
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

include Makefile.common

noinst_LIBRARIES = libui.a

CLEANFILES = \
	libui.a		\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

wireshark-tap-register.c: $(WIRESHARK_TAP_SRC) $(top_srcdir)/make-tapreg-dotc
	@echo Making wireshark-tap-register.c
	@$(top_srcdir)/make-tapreg-dotc wireshark-tap-register.c $(srcdir) $(WIRESHARK_TAP_SRC)

noinst_HEADERS = \
	about_dlg.h	\
	airpcap_dlg.h \
	airpcap_gui_utils.h \
	capture_dlg.h	\
	capture_file_dlg.h	\
	capture_if_details_dlg.h	\
	capture_prefs.h	\
	cfilter_combo_utils.h \
	color_dlg.h	\
	colors.h	\
	column_prefs.h	\
	compat_macros.h	\
	conversations_table.h \
	decode_as_dlg.h	\
	decode_as_dcerpc.h \
	dfilter_expr_dlg.h \
	dlg_utils.h	\
	expert_comp_table.h	\
	file_dlg.h	\
	fileset_dlg.h	\
	filter_dlg.h	\
	find_dlg.h	\
	firewall_dlg.h	\
	follow_dlg.h	\
	font_utils.h	\
	goto_dlg.h	\
	graph_analysis.h \
	gsm_map_stat.h	\
	gtkglobals.h	\
	gui_stat_util.h \
	gui_prefs.h	\
	gui_utils.h	\
	help_dlg.h	\
	hostlist_table.h \
	isprint.h	\
	keys.h		\
	layout_prefs.h	\
	main.h		\
	menu.h		\
	mtp3_stat.h	\
	nameres_prefs.h	\
	packet_history.h	\
	packet_list.h	\
	packet_win.h	\
	plugins_dlg.h	\
	prefs_dlg.h	\
	print_prefs.h	\
	proto_dlg.h	\
	proto_draw.h	\
	proto_hier_stats_dlg.h	\
	range_utils.h \
	recent.h	\
	rtp_analysis.h	\
	rtp_stream.h	\
	rtp_stream_dlg.h \
	mcast_stream.h  \
	mcast_stream_dlg.h \
	sat.h		\
	sctp_stat.h	\
	service_response_time_table.h	\
	gui_stat_menu.h	\
	ssl-dlg.h	\
	stream_prefs.h	\
	summary_dlg.h   \
	supported_protos_dlg.h   \
	text_page.h	\
	toolbar.h	\
	voip_calls.h	\
	voip_calls_dlg.h \
	webbrowser.h

if USE_GTK2
libui_a_SOURCES = \
	$(WIRESHARK_GTK_SRC) \
	$(noinst_HEADERS) \
	$(WIRESHARK_TAP_SRC)
else
libui_a_SOURCES = \
	ethclist.c	\
	ethclist.h	\
	$(WIRESHARK_GTK_SRC) \
	$(noinst_HEADERS) \
	$(WIRESHARK_TAP_SRC)
endif

libui_a_DEPENDENCIES = 

EXTRA_DIST = \
	airpcap_dlg.c \
	airpcap_gui_utils.c \
	capture_if_details_dlg.c	\
	doxygen.cfg.in \
	ethclist.c	\
	ethclist.h	\
	Makefile.common \
	Makefile.nmake \
	print_mswin.c  \
	print_mswin.h  \
	win32-file-dlg.c \
	win32-file-dlg.h

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap $(LIBGCRYPT_CFLAGS)

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

