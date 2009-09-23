# CMakeLists.txt
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
#

set(DISSECTOR_SRC
	packet-wmx.c
)

set(DISSECTOR_SUPPORT_SRC
	wimax_ffb_decoder.c
	wimax_fch_decoder.c
	wimax_pdu_decoder.c
	wimax_cdma_code_decoder.c
	wimax_hack_decoder.c
	wimax_phy_attributes_decoder.c
	mac_hd_generic_decoder.c
	mac_hd_type1_decoder.c
	mac_hd_type2_decoder.c
	mac_mgmt_msg_decoder.c
	msg_dcd.c
	msg_ucd.c
	msg_dlmap.c
	msg_ulmap.c
	msg_rng_req.c
	msg_rng_rsp.c
	msg_reg_req.c
	msg_reg_rsp.c
	msg_dreg.c
	msg_dsa.c
	msg_dsc.c
	msg_dsd.c
	msg_arq.c
	msg_sbc.c
	msg_pkm.c
	msg_aas_fbck.c
	msg_fpc.c
	msg_pmc.c
	msg_prc_lt_ctrl.c
	msg_aas_beam.c
	msg_res_cmd.c
	msg_rep.c
	msg_clk_cmp.c
	msg_dsx_rvd.c
	wimax_harq_map_decoder.c
	wimax_compact_dlmap_ie_decoder.c
	wimax_compact_ulmap_ie_decoder.c
	wimax_utils.c
	crc.c
	crc_data.c
	wimax_tlv.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_COMMAND(
# FIXME: Only the Python stuff has been implemented
#        Make this into a MACRO, to avoid duplication with epan/
#plugin.c: $(DISSECTOR_SRC) $(top_srcdir)/tools/make-dissector-reg \
#    $(top_srcdir)/tools/make-dissector-reg.py
#        @if test -n "$(PYTHON)"; then \
#                echo Making plugin.c with python ; \
#                $(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
#                    plugin $(DISSECTOR_SRC) ; \
#        else \
#                echo Making plugin.c with shell script ; \
#                $(top_srcdir)/tools/make-dissector-reg $(srcdir) \
#                    $(plugin_src) plugin $(DISSECTOR_SRC) ; \
#        fi

    OUTPUT plugin.c
    COMMAND ${PYTHON_EXECUTABLE}
      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
      ${CMAKE_CURRENT_SOURCE_DIR}
      plugin
      ${DISSECTOR_SRC}
    DEPENDS
      ${DISSECTOR_SRC}
      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg
      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
)

# todo
# Do I need any of this or is this handled by type MODULE?
# wimax_la_LDFLAGS = -module -avoid-version

add_library(wimax MODULE
	${PLUGIN_FILES}
)

install(TARGETS wimax
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

