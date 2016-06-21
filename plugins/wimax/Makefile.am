# Makefile.am
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
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = wimax

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-wmx.c \
	wimax_cdma_code_decoder.c	\
	wimax_compact_dlmap_ie_decoder.c	\
	wimax_compact_ulmap_ie_decoder.c	\
	wimax_fch_decoder.c	\
	wimax_ffb_decoder.c	\
	wimax_hack_decoder.c	\
	wimax_harq_map_decoder.c	\
	wimax_pdu_decoder.c	\
	wimax_phy_attributes_decoder.c	\
	mac_hd_generic_decoder.c	\
	mac_hd_type1_decoder.c	\
	mac_hd_type2_decoder.c	\
	mac_mgmt_msg_decoder.c	\
	msg_aas_fbck.c	\
	msg_aas_beam.c	\
	msg_arq.c	\
	msg_clk_cmp.c	\
	msg_dcd.c	\
	msg_dlmap.c	\
	msg_dreg.c	\
	msg_dsa.c	\
	msg_dsc.c	\
	msg_dsd.c	\
	msg_dsx_rvd.c	\
	msg_fpc.c	\
	msg_pkm.c	\
	msg_pmc.c	\
	msg_prc_lt_ctrl.c	\
	msg_reg_req.c	\
	msg_reg_rsp.c	\
	msg_rep.c	\
	msg_res_cmd.c	\
	msg_rng_req.c	\
	msg_rng_rsp.c	\
	msg_sbc.c	\
	msg_ucd.c	\
	msg_ulmap.c	\
	wimax_utils.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES) \
	crc.c	\
	crc_data.c	\
	wimax_tlv.c

# Headers.
CLEAN_HEADER_FILES = \
	crc.h		\
	wimax_bits.h	\
	wimax_compact_dlmap_ie_decoder.h	\
	wimax_compact_ulmap_ie_decoder.h	\
	wimax_mac.h	\
	wimax_tlv.h	\
	wimax_utils.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = wimax.la

wimax_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

wimax_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

wimax_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

wimax_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	wimax \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	CMakeLists.txt		\
	README.wimax
