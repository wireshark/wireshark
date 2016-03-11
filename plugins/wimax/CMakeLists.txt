# CMakeLists.txt
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
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(wimax 1 1 0 0)

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

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(wimax)

install(TARGETS wimax
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  wimax
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
)
