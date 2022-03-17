# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

if(EXTCAP_ANDROIDDUMP_LIBPCAP)
	set(ANDROIDDUMP_USE_LIBPCAP 1)
endif()

if(LIBSSH_FOUND)
	include(CMakePushCheckState)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_INCLUDES ${LIBSSH_INCLUDE_DIRS})
	set(CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
	check_function_exists(ssh_userauth_agent LIBSSH_USERAUTH_AGENT_FOUND)
	cmake_pop_check_state()
endif()

# Ensure "run/extcap" exists
# add_custom_command(OUTPUT "${DATAFILE_DIR}/extcap"
# 	COMMAND ${CMAKE_COMMAND} -E make_directory
# 		"${DATAFILE_DIR}/extcap"
# )
# list(APPEND copy_data_files_depends "${DATAFILE_DIR}/extcap")


macro(set_extcap_executable_properties _executable)
	set_target_properties(${_executable} PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables/Extcaps"
		INSTALL_RPATH "${EXTCAP_INSTALL_RPATH}"
	)
	if(MSVC)
		set_target_properties(${_executable} PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
	endif()

	set(PROGLIST ${PROGLIST} ${_executable})

	if(MSVC)
		set_target_properties(${_executable} PROPERTIES
			RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/extcap
			RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/run/Debug/extcap
			RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/run/Release/extcap
			RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/run/MinSizeRel/extcap
			RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/run/RelWithDebInfo/extcap
		)
	else()
		set_target_properties(${_executable} PROPERTIES
			RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/extcap
		)
		if(ENABLE_APPLICATION_BUNDLE)
			if(NOT CMAKE_CFG_INTDIR STREQUAL ".")
				# Xcode
				set_target_properties(${_executable} PROPERTIES
					RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/$<CONFIG>/Wireshark.app/Contents/MacOS/extcap
				)
			else()
				set_target_properties(${_executable} PROPERTIES
					RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/extcap
				)
				# Create a convenience link from run/<name> to its respective
				# target in the application bundle.
				add_custom_target(${_executable}-symlink
					COMMAND ln -s -f
						Wireshark.app/Contents/MacOS/extcap/${_executable}
						${CMAKE_BINARY_DIR}/run/${_executable}
				)
				add_dependencies(${_executable} ${_executable}-symlink)
			endif()
		endif()
	endif()

	if (MINGW)
		set_target_properties(${_executable} PROPERTIES
			LINK_OPTIONS -municode
		)
	endif()
endmacro()

macro(set_extlog_executable_properties _executable)
	if(ENABLE_APPLICATION_BUNDLE)
		if(NOT CMAKE_CFG_INTDIR STREQUAL ".")
			# Xcode
			set_target_properties(${_executable} PROPERTIES
				RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/$<CONFIG>/Logray.app/Contents/MacOS/extcap
			)
		else()
			set_target_properties(${_executable} PROPERTIES
				RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Logray.app/Contents/MacOS/extcap
			)
			# Create a convenience link from run/<name> to its respective
			# target in the application bundle.
			add_custom_target(${_executable}-symlink
				COMMAND ln -s -f
					Logray.app/Contents/MacOS/extcap/${_executable}
					${CMAKE_BINARY_DIR}/run/${_executable}
			)
			add_dependencies(${_executable} ${_executable}-symlink)
		endif()
	endif()
endmacro()

add_custom_target(extcaps)

add_library(extcap-base OBJECT extcap-base.c)
if(LIBSSH_FOUND)
	add_library(ssh-base OBJECT ssh-base.c)
	target_include_directories(ssh-base SYSTEM
		PRIVATE
			${LIBSSH_INCLUDE_DIRS}
	)
endif()

if(BUILD_androiddump)
	if(EXTCAP_ANDROIDDUMP_LIBPCAP)
		if(HAVE_LIBPCAP)
			set(androiddump_LIBS
				ui
				wiretap
				wsutil
				${WIN_WS2_32_LIBRARY}
				$<$<BOOL:${PCAP_FOUND}>:pcap::pcap>
			)
		else()
			message(FATAL_ERROR "You are trying to build androiddump with libpcap but do not have it")
		endif()
	else()
		set(androiddump_LIBS
			ui
			wiretap
			wsutil
			${ZLIB_LIBRARIES}
			${CMAKE_DL_LIBS}
			${WIN_WS2_32_LIBRARY}
		)
	endif()
	set(androiddump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		androiddump.c
	)

	set_executable_resources(androiddump "Androiddump")
	add_executable(androiddump ${androiddump_FILES})
	set_extcap_executable_properties(androiddump)
	target_link_libraries(androiddump ${androiddump_LIBS})
	install(TARGETS androiddump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps androiddump)
endif()

if(BUILD_sshdump AND LIBSSH_FOUND)
	set(sshdump_LIBS
		wsutil
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
		${LIBSSH_LIBRARIES}
	)
	set(sshdump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		$<TARGET_OBJECTS:ssh-base>
		sshdump.c
	)

	set_executable_resources(sshdump "Sshdump")
	add_executable(sshdump ${sshdump_FILES})
	set_extcap_executable_properties(sshdump)
	target_link_libraries(sshdump ${sshdump_LIBS})
	target_include_directories(sshdump SYSTEM PRIVATE ${LIBSSH_INCLUDE_DIRS})
	install(TARGETS sshdump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps sshdump)
elseif (BUILD_sshdump)
	#message( WARNING "Cannot find libssh, cannot build sshdump" )
endif()

if(BUILD_ciscodump AND LIBSSH_FOUND)
	set(ciscodump_LIBS
		writecap
		wsutil
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
		${LIBSSH_LIBRARIES}
	)
	set(ciscodump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		$<TARGET_OBJECTS:ssh-base>
		ciscodump.c
	)

	set_executable_resources(ciscodump "Ciscodump")
	add_executable(ciscodump ${ciscodump_FILES})
	set_extcap_executable_properties(ciscodump)
	target_link_libraries(ciscodump ${ciscodump_LIBS})
	target_include_directories(ciscodump SYSTEM PRIVATE ${LIBSSH_INCLUDE_DIRS})
	install(TARGETS ciscodump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps ciscodump)
elseif (BUILD_ciscodump)
	#message( WARNING "Cannot find libssh, cannot build ciscodump" )
endif()

if(BUILD_wifidump AND LIBSSH_FOUND)
	set(wifidump_LIBS
		writecap
		wsutil
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
		${LIBSSH_LIBRARIES}
	)
	set(wifidump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		$<TARGET_OBJECTS:ssh-base>
		wifidump.c
	)

	set_executable_resources(wifidump "Wifidump")
	add_executable(wifidump ${wifidump_FILES})
	set_extcap_executable_properties(wifidump)
	target_link_libraries(wifidump ${wifidump_LIBS})
	target_include_directories(wifidump SYSTEM PRIVATE ${LIBSSH_INCLUDE_DIRS})
	install(TARGETS wifidump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps wifidump)
elseif (BUILD_wifidump)
	#message( WARNING "Cannot find libssh, cannot build wifidump" )
endif()

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	set(dpauxmon_LIBS
		wsutil
		writecap
		${CMAKE_DL_LIBS}
		${NL_LIBRARIES}
	)
	set(dpauxmon_FILES
		$<TARGET_OBJECTS:extcap-base>
		dpauxmon.c
	)

	set_executable_resources(dpauxmon "dpauxmon")
	add_executable(dpauxmon ${dpauxmon_FILES})
	set_extcap_executable_properties(dpauxmon)
	target_link_libraries(dpauxmon ${dpauxmon_LIBS})
	target_include_directories(dpauxmon SYSTEM PRIVATE ${NL_INCLUDE_DIRS})
	install(TARGETS dpauxmon RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps dpauxmon)
elseif (BUILD_dpauxmon)
	#message( WARNING "Cannot find libnl3, cannot build dpauxmon" )
endif()

if(BUILD_udpdump)
	set(udpdump_LIBS
		wsutil
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
		wsutil
		writecap
	)
	set(udpdump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		udpdump.c
	)

	set_executable_resources(udpdump "udpdump")
	add_executable(udpdump ${udpdump_FILES})
	set_extcap_executable_properties(udpdump)
	target_link_libraries(udpdump ${udpdump_LIBS})
	install(TARGETS udpdump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps udpdump)
endif()

if(BUILD_randpktdump)
	set(randpktdump_LIBS
		randpkt_core
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
	)
	set(randpktdump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		randpktdump.c
	)

	set_executable_resources(randpktdump "randpktdump")
	add_executable(randpktdump ${randpktdump_FILES})
	set_extcap_executable_properties(randpktdump)
	target_link_libraries(randpktdump ${randpktdump_LIBS})
	install(TARGETS randpktdump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps randpktdump)
endif()


if(BUILD_etwdump AND WIN32)
	set(etwdump_LIBS
		wiretap
		wsutil
		tdh
		wevtapi
		rpcrt4
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
		${WIN_WS2_32_LIBRARY}
	)
	set(etwdump_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:extcap-base>
		etwdump.c
		etl.c
		etw_message.c
		etw_ndiscap.c
	)

	set_executable_resources(etwdump "etwdump")
	add_executable(etwdump ${etwdump_FILES})
	set_extcap_executable_properties(etwdump)
	target_link_libraries(etwdump ${etwdump_LIBS})
	install(TARGETS etwdump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps etwdump)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	set(sdjournal_LIBS
		wiretap
		writecap
		wsutil
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
		${SYSTEMD_LIBRARIES}
		${GCRYPT_LIBRARIES}
	)
	set(sdjournal_FILES
		$<TARGET_OBJECTS:extcap-base>
		sdjournal.c
	)

	set_executable_resources(sdjournal "sdjournal")
	add_executable(sdjournal ${sdjournal_FILES})
	set_extcap_executable_properties(sdjournal)
	target_link_libraries(sdjournal ${sdjournal_LIBS})
	target_include_directories(sdjournal SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIRS})
	install(TARGETS sdjournal RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps sdjournal)
endif()

if(BUILD_falcodump AND SINSP_FOUND)
	set(falcodump_LIBS
		wsutil
		${SINSP_LINK_LIBRARIES}
		${CMAKE_DL_LIBS}
		${GCRYPT_LIBRARIES}
	)
	set(falcodump_FILES
		$<TARGET_OBJECTS:extcap-base>
		falcodump.cpp
	)

	set_executable_resources(falcodump "falcodump")
	add_executable(falcodump ${falcodump_FILES})
	set_extlog_executable_properties(falcodump)
	target_link_libraries(falcodump ${falcodump_LIBS})
	target_include_directories(falcodump SYSTEM PRIVATE ${SINSP_INCLUDE_DIRS})
	install(TARGETS falcodump RUNTIME DESTINATION ${EXTCAP_INSTALL_LIBDIR})
	add_dependencies(extcaps falcodump)

	# XXX Hack; We need to fix this in falcosecurity-libs.
	target_compile_definitions(falcodump PRIVATE HAVE_STRLCPY=1)

endif()

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
