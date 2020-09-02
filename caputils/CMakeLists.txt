# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#


if(UNIX)
	set(PLATFORM_CAPUTILS_SRC
		capture-pcap-util-unix.c
	)
endif()

if(WIN32)
	set(PLATFORM_CAPUTILS_SRC
		capture_win_ifnames.c
		capture-wpcap.c
	)
endif()

set(CAPUTILS_SRC
	${PLATFORM_CAPUTILS_SRC}
	capture-pcap-util.c
	iface_monitor.c
	ws80211_utils.c
)

if (AIRPCAP_FOUND)
	set(CAPUTILS_SRC
		${CAPUTILS_SRC}
		airpcap_loader.c
	)
endif()

set_source_files_properties(
	${CAPUTILS_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


add_library(caputils STATIC
	${CAPUTILS_SRC}
)

target_link_libraries(caputils
	PUBLIC
		wsutil
		$<$<BOOL:${PCAP_FOUND}>:pcap::pcap>
	PRIVATE
		${NL_LIBRARIES}
)

target_include_directories(caputils SYSTEM
	PRIVATE
		${NL_INCLUDE_DIRS}
)

if(WIN32)
	target_link_libraries(caputils PRIVATE "iphlpapi.lib")
endif(WIN32)

set_target_properties(caputils PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")

CHECKAPI(
	NAME
	  caputils-base
	SWITCHES
	SOURCES
	  ${CAPUTILS_SRC}
)
CHECKAPI(
	NAME
	  caputils-todo
	SWITCHES
	  -M
	SOURCES
	  ${CAPUTILS_SRC}
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
