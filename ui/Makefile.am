# Makefile.am
# Automake file for the common-to-all-toolkits user interface routines
# for Wireshark
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) -DDOC_DIR=\"$(docdir)\" \
	$(GLIB_CFLAGS) $(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)

noinst_LIBRARIES = libui.a libui_dirty.a

# Generated header files that we want in the distribution.
GENERATED_HEADER_FILES = \
	text_import_scanner_lex.h

# Generated C source files that we want in the distribution.
GENERATED_C_FILES =

DIRTY_GENERATED_C_FILES = \
	text_import_scanner.c

# All the generated files we want in the distribution.
GENERATED_FILES = \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES) \
	$(DIRTY_GENERATED_C_FILES)

# Files that generate compileable files
GENERATOR_FILES = \
	text_import_scanner.l

WIRESHARK_UI_SRC = \
	alert_box.c		\
	capture.c		\
	capture_ui_utils.c	\
	commandline.c		\
	console.c		\
	decode_as_utils.c	\
	export_object.c		\
	export_object_dicom.c	\
	export_object_http.c	\
	export_object_smb.c	\
	export_object_tftp.c	\
	export_pdu_ui_utils.c	\
	firewall_rules.c	\
	iface_lists.c		\
	io_graph_item.c		\
	language.c		\
	help_url.c		\
	mcast_stream.c		\
	packet_list_utils.c	\
	persfilepath_opt.c	\
	preference_utils.c	\
	profile.c		\
	proto_hier_stats.c	\
	recent.c		\
	rtp_media.c		\
	rtp_stream.c		\
	service_response_time.c	\
	software_update.c	\
	ssl_key_export.c	\
	tap_export_pdu.c	\
	tap-iax2-analysis.c	\
	tap-rlc-graph.c		\
	tap-rtp-common.c	\
	tap-sctp-analysis.c	\
	tap-sequence-analysis.c	\
	tap-tcp-stream.c	\
	text_import.c		\
	time_shift.c		\
	traffic_table_ui.c	\
	util.c			\
	voip_calls.c

WIRESHARK_UI_INCLUDES = \
	alert_box.h		\
	all_files_wildcard.h	\
	capture.h		\
	capture_globals.h	\
	capture_ui_utils.h	\
	commandline.h		\
	console.h		\
	decode_as_utils.h	\
	export_object.h		\
	export_pdu_ui_utils.h	\
	last_open_dir.h		\
	file_dialog.h		\
	help_url.h		\
	packet_list_utils.h	\
	firewall_rules.h	\
	iface_lists.h		\
	io_graph_item.h		\
	language.h		\
	mcast_stream.h		\
	main_statusbar.h	\
	persfilepath_opt.h	\
	preference_utils.h	\
	profile.h		\
	progress_dlg.h		\
	proto_hier_stats.h	\
	recent.h		\
	recent_utils.h		\
	rtp_media.h		\
	rtp_stream.h		\
	service_response_time.h	\
	simple_dialog.h		\
	software_update.h	\
	ssl_key_export.h	\
	tap_export_pdu.h	\
	tap-iax2-analysis.h	\
	tap-rlc-graph.h		\
	tap-rtp-analysis.h	\
	tap-rtp-common.h	\
	tap-sctp-analysis.h	\
	tap-sequence-analysis.h	\
	tap-tcp-stream.h	\
	text_import.h		\
	text_import_scanner.h	\
	time_shift.h		\
	traffic_table_ui.h	\
	ui_util.h		\
	util.h			\
	voip_calls.h

# All sources that should be put in the source distribution tarball
libui_a_SOURCES = \
	$(WIRESHARK_UI_SRC) \
	$(WIRESHARK_UI_INCLUDES) \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES)

libui_dirty_a_SOURCES = \
	$(DIRTY_GENERATED_C_FILES)

libui_dirty_a_CFLAGS = $(GENERATED_CFLAGS)

EXTRA_DIST = \
	.editorconfig			\
	$(GENERATOR_FILES)		\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	win32

BUILT_SOURCES = $(GENERATED_HEADER_FILES)

CLEANFILES = \
	doxygen-ui.tag	\
	libui.a		\
	libui_dirty.a	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

text_import_scanner_lex.h: text_import_scanner.c

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_UI_SRC)

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir) \
	$(WIRESHARK_UI_SRC)
