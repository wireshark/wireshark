# Makefile.am
# Automake file for the GTK interface routines for Ethereal
#
# $Id: Makefile.am,v 1.73 2003/11/05 09:04:17 sahlberg Exp $
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

noinst_LIBRARIES = libui.a

CLEANFILES = \
	libui.a		\
	*~

ETHEREAL_TAP_SRC = \
       	bootp_stat.c    \
	dcerpc_stat.c	\
	endpoint_talkers_eth.c	\
	endpoint_talkers_fc.c	\
	endpoint_talkers_fddi.c	\
	endpoint_talkers_ip.c	\
	endpoint_talkers_ipx.c	\
	endpoint_talkers_tcpip.c	\
	endpoint_talkers_tr.c	\
	endpoint_talkers_udpip.c	\
	fc_stat.c	\
	h225_counter.c  \
	http_stat.c	\
	io_stat.c	\
	ldap_stat.c	\
	mgcp_stat.c	\
	rpc_stat.c	\
	rpc_progs.c	\
	smb_stat.c	\
	rtp_analysis.c  \
	rtp_stream.c    \
	rtp_stream_dlg.c \
	wsp_stat.c

ethereal-tap-register.c: $(ETHEREAL_TAP_SRC) $(top_srcdir)/make-tapreg-dotc
	@echo Making ethereal-tap-register.c
	@$(top_srcdir)/make-tapreg-dotc ethereal-tap-register.c $(srcdir) $(ETHEREAL_TAP_SRC)

if USE_GTK2
libui_a_SOURCES = \
	capture_combo_utils.c \
	capture_combo_utils.h \
	capture_dlg.c	\
	capture_dlg.h	\
	capture_prefs.c	\
	capture_prefs.h	\
	color_dlg.c	\
	color_dlg.h	\
	color_filters.c	\
	color_filters.h	\
	color_utils.c	\
	color_utils.h	\
	colors.c	\
	colors.h	\
	column_prefs.c	\
	column_prefs.h	\
	compat_macros.h	\
	decode_as_dlg.c	\
	decode_as_dlg.h	\
	dfilter_expr_dlg.c \
	dfilter_expr_dlg.h \
	display_opts.c	\
	display_opts.h	\
	dlg_utils.c	\
	dlg_utils.h	\
	endpoint_talkers_table.c \
	endpoint_talkers_table.h \
	ethereal-tap-register.c \
	file_dlg.c	\
	file_dlg.h	\
	filter_prefs.c	\
	filter_prefs.h	\
	find_dlg.c	\
	find_dlg.h	\
	follow_dlg.c	\
	follow_dlg.h	\
	goto_dlg.c	\
	goto_dlg.h	\
	gtkglobals.h	\
	gtk_stat_util.c \
	gtk_stat_util.h \
	gui_prefs.c	\
	gui_prefs.h	\
	help_dlg.c	\
	help_dlg.h	\
	keys.h		\
	main.c		\
	main.h		\
	menu.c		\
	menu.h		\
	nameres_prefs.c	\
	nameres_prefs.h	\
	packet_list.c	\
	packet_win.c	\
	packet_win.h	\
	plugins_dlg.c	\
	prefs_dlg.c	\
	prefs_dlg.h	\
	print_dlg.c	\
	print_prefs.c   \
	print_prefs.h	\
	progress_dlg.c	\
	proto_dlg.c	\
	proto_dlg.h	\
	proto_draw.c	\
	proto_draw.h	\
	proto_hier_stats_dlg.h	\
	proto_hier_stats_dlg.c	\
	rtp_analysis.h	\
	rtp_stream.h	\
	rtp_stream_dlg.h \
	service_response_time_table.c	\
	service_response_time_table.h	\
	simple_dialog.c	\
	stream_prefs.c	\
	stream_prefs.h	\
	summary_dlg.c   \
	summary_dlg.h   \
	tcp_graph.c     \
	tcp_graph.h     \
	toolbar.c       \
	toolbar.h       \
	ui_util.c       \
	ui_util.h	\
	$(ETHEREAL_TAP_SRC)
else
libui_a_SOURCES = \
	capture_combo_utils.c \
	capture_combo_utils.h \
	capture_dlg.c	\
	capture_dlg.h	\
	capture_prefs.c	\
	capture_prefs.h	\
	color_dlg.c	\
	color_dlg.h	\
	color_filters.c	\
	color_filters.h	\
	color_utils.c	\
	color_utils.h	\
	colors.c	\
	colors.h	\
	column_prefs.c	\
	column_prefs.h	\
	decode_as_dlg.c	\
	decode_as_dlg.h	\
	dfilter_expr_dlg.c \
	dfilter_expr_dlg.h \
	display_opts.c	\
	display_opts.h	\
	dlg_utils.c	\
	dlg_utils.h	\
	endpoint_talkers_table.c \
	endpoint_talkers_table.h \
	ethereal-tap-register.c \
	file_dlg.c	\
	file_dlg.h	\
	filter_prefs.c	\
	filter_prefs.h	\
	find_dlg.c	\
	find_dlg.h	\
	follow_dlg.c	\
	follow_dlg.h	\
	goto_dlg.c	\
	goto_dlg.h	\
	gtkclist_v12.c	\
	gtkclist_v12.h	\
	gtkglobals.h	\
	gtk_stat_util.c \
	gtk_stat_util.h \
	gui_prefs.c	\
	gui_prefs.h	\
	help_dlg.c	\
	help_dlg.h	\
	keys.h		\
	main.c		\
	main.h		\
	menu.c		\
	menu.h		\
	nameres_prefs.c	\
	nameres_prefs.h	\
	packet_list.c	\
	packet_win.c	\
	packet_win.h	\
	plugins_dlg.c	\
	prefs_dlg.c	\
	prefs_dlg.h	\
	print_dlg.c	\
	print_prefs.c   \
	print_prefs.h	\
	progress_dlg.c	\
	proto_dlg.c	\
	proto_dlg.h	\
	proto_draw.c	\
	proto_draw.h	\
	proto_hier_stats_dlg.h	\
	proto_hier_stats_dlg.c	\
	rtp_analysis.h	\
	rtp_stream.h	\
	rtp_stream_dlg.h \
	service_response_time_table.c	\
	service_response_time_table.h	\
	simple_dialog.c	\
	stream_prefs.c	\
	stream_prefs.h	\
	summary_dlg.c   \
	summary_dlg.h   \
	tcp_graph.c     \
	tcp_graph.h     \
	toolbar.c       \
	toolbar.h       \
	ui_util.c       \
	ui_util.h	\
	$(ETHEREAL_TAP_SRC)
endif

EXTRA_DIST = \
	Makefile.nmake \
	compat_macros.h \
	print_mswin.c  \
	print_mswin.h

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap
