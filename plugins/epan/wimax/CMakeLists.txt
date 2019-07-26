# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(wimax 1 2 0 0)

set(DISSECTOR_SRC
	packet-m2m.c
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

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(wimax epan)

target_link_libraries(wimax epan)

install_plugin(wimax epan)

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

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
