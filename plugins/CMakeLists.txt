# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# Note we have already called include(UseCustomIncludes) in the root dir
# XXX - Move CMakeFilesCustom.txt for custom plugins here?

add_custom_target(plugins)
set_target_properties(plugins PROPERTIES FOLDER "Plugins")
set(WIRESHARK_PLUGIN_SRC_DIRS
	epan/ethercat
	epan/gryphon
	epan/irda
	epan/mate
	epan/opcua
	epan/profinet
	epan/stats_tree
	epan/transum
	epan/unistim
	epan/wimax
	epan/wimaxasncp
	epan/wimaxmacphy
	epan/dfilter/ipaddr
	wiretap/usbdump
	codecs/G711
	codecs/l16_mono
	codecs/l24
	${CUSTOM_PLUGIN_SRC_DIR}
)
set(STRATOSHARK_PLUGIN_SRC_DIRS)
if(SINSP_FOUND)
	list(APPEND STRATOSHARK_PLUGIN_SRC_DIRS
		epan/falco_events
	)
endif()
if(SPANDSP_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/G722
		codecs/G726
	)
endif()
if(BCG729_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/G729
	)
endif()
if(AMRNB_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/amrnb
	)
endif()
if(AMRWB_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/amrwb
	)
endif()
if(ILBC_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/iLBC
	)
endif()
if(OPUS_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/opus_dec
	)
endif()
if(SBC_FOUND)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		codecs/sbc
	)
endif()

# Build demo plugin, only if asked explicitly
if(ENABLE_PLUGIN_IFDEMO)
	list(APPEND WIRESHARK_PLUGIN_SRC_DIRS
		ui/pluginifdemo
	)
endif()

foreach(_plugin_src_dir ${WIRESHARK_PLUGIN_SRC_DIRS} ${STRATOSHARK_PLUGIN_SRC_DIRS})
	cmake_path(SET _plugins_dir "plugins")
	cmake_path(IS_PREFIX _plugins_dir "${_plugin_src_dir}" _is_plugins_subdir)
	# If custom in-tree plugins have the "plugins" prefix, strip it off
	if(_is_plugins_subdir)
		message(DEBUG "${_plugin_src_dir} is a subdir of plugins, removing prefix")
		cmake_path(RELATIVE_PATH _plugin_src_dir BASE_DIRECTORY "${_plugins_dir}")
	endif()
	add_subdirectory( ${_plugin_src_dir} )
endforeach()
