# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# List of dissectors compiled below, which should be turned off.
# This is done to avoid single fuzzer (like IP) to call UDP protocols, which can go back to IP, and so on..
# While doing so might find some bugs, but it's likely to be the problem for too big corpus in oss-fuzzer
# (see: https://github.com/google/oss-fuzz/issues/1087).
# + udplite - it's sharing most of code with UDP.
set(FUZZ_DISABLED_DISSECTORS ip udp udplite ospf bgp dhcp json)

set(FUZZ_DISSECTORS ip)
set(FUZZ_IP_PROTO_DISSECTORS udp ospf)

set(FUZZ_TCP_PORT_DISSECTORS bgp)
# list(APPEND FUZZ_TCP_PORT_DISSECTORS bzr)     # disabled, cause of known problem.
# list(APPEND FUZZ_TCP_PORT_DISSECTORS echo)    # disabled, too simple.

set(FUZZ_UDP_PORT_DISSECTORS dns dhcp)
# list(FUZZ_UDP_PORT_DISSECTORS bfd)            # disabled, too simple.

set(FUZZ_MEDIA_TYPE_DISSECTORS json)

set(fuzzshark_LIBS
	ui
	wiretap
	epan
	${VERSION_INFO_LIBS}
)
if(OSS_FUZZ)
	if("$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
		message(FATAL_ERROR "LIB_FUZZING_ENGINE is not set!")
	endif()
	list(APPEND fuzzshark_LIBS $ENV{LIB_FUZZING_ENGINE})
endif()
set(fuzzshark_FILES
	fuzzshark.c
	$<TARGET_OBJECTS:version_info>
)
set(FUZZ_LINK_FLAGS "${WS_LINK_FLAGS}")
if(ENABLE_FUZZER)
	set(FUZZ_LINK_FLAGS "${FUZZ_LINK_FLAGS} -fsanitize=fuzzer")
endif()
if(OSS_FUZZ)
	# libFuzzingEngine.a is not position independent, so cannot use -pie.
	set(FUZZ_LINK_FLAGS "${FUZZ_LINK_FLAGS} -no-pie")
endif()

# Convert the list of disabled dissectors from a;b;c -> "a", "b", "c"
# for use in fuzzshark.c (macro)
string(REGEX REPLACE "([^;]+)" "\"\\1\"" FUZZ_DISABLED_DISSECTORS_MACRO "${FUZZ_DISABLED_DISSECTORS}")
string(REPLACE ";" ", " FUZZ_DISABLED_DISSECTORS_MACRO "${FUZZ_DISABLED_DISSECTORS_MACRO}")

# Targets that are build via all-fuzzers:
# - fuzzshark: a non-specific fuzz target, configurable through env vars (requires BUILD_fuzzshark)
# - fuzzshark_<target>: fuzz target for a specific dissector target.
# - fuzzshark_<table>-<target>: fuzz target for a specific dissector via a dissector table.
add_custom_target(all-fuzzers)

function(fuzzshark_set_common_options fuzzer_name)
	# Sanitizers require a C++ runtime, so use a C++ linker.
	set_target_properties(${fuzzer_name} PROPERTIES
		FOLDER "Fuzzers"
		LINK_FLAGS "${FUZZ_LINK_FLAGS}"
		LINKER_LANGUAGE "CXX"
	)
	target_link_libraries(${fuzzer_name} ${fuzzshark_LIBS})
	add_dependencies(all-fuzzers ${fuzzer_name})
endfunction()

if(BUILD_fuzzshark)
	if(NOT (ENABLE_FUZZER OR OSS_FUZZ))
		# libFuzzer includes a main routine that enables fuzzing. If
		# support for fuzzing was not enabled, add a small standalone
		# target that can be used to test-compile fuzzshark.c.
		list(APPEND fuzzshark_FILES StandaloneFuzzTargetMain.c)
	endif()
	add_executable(fuzzshark ${fuzzshark_FILES})
	fuzzshark_set_common_options(fuzzshark)
endif()

# Create a new dissector fuzzer target.
# If <dissector_table> is empty, <name> will be called directly.
# If <dissector_table> is non-empty, a dissector with filter name <name> will be
# looked up in dissector table <dissector_table>.
function(generate_fuzzer dissector_table name)
	if(NOT (ENABLE_FUZZER OR OSS_FUZZ))
		return()
	endif()

	if(dissector_table STREQUAL "")
		set(fuzzer_name fuzzshark_${name})
	else()
		# "ip.proto" and "udp" -> "ip_proto-udp"
		set(fuzzer_name fuzzshark_${dissector_table}-${name})
		string(REPLACE "." "_" fuzzer_name ${fuzzer_name})
	endif()

	add_executable(${fuzzer_name} EXCLUDE_FROM_ALL ${fuzzshark_FILES})
	fuzzshark_set_common_options(${fuzzer_name})
	target_compile_definitions(${fuzzer_name} PRIVATE
		FUZZ_DISSECTOR_LIST=${FUZZ_DISABLED_DISSECTORS_MACRO}
		FUZZ_DISSECTOR_TARGET="${name}"
	)
	if(NOT dissector_table STREQUAL "")
		target_compile_definitions(${fuzzer_name} PRIVATE
			FUZZ_DISSECTOR_TABLE="${dissector_table}")
	endif()
endfunction()

# Add fuzzer targets for every dissector in list FUZZ_<table-var>_DISSECTORS,
# where <table-var> changes a <table> such as "ip.proto" into "IP_PROTO".
function(add_table_fuzzers table)
	string(REPLACE "." "_" table_var ${table})
	string(TOUPPER "${table_var}" table_var)
	foreach(dissector IN LISTS FUZZ_${table_var}_DISSECTORS)
		generate_fuzzer(${table} ${dissector})
	endforeach()
endfunction()

foreach(dissector IN LISTS FUZZ_DISSECTORS)
	generate_fuzzer("" ${dissector})
endforeach()

add_table_fuzzers("ip.proto")
add_table_fuzzers("tcp.port")
add_table_fuzzers("udp.port")
add_table_fuzzers("media_type")

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
