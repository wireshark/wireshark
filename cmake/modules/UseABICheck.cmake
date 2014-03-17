#
# ABI Check related macros
#
# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12

MACRO(ABICHECK _libname)
	set(ABICHECK_TMPDIR ${CMAKE_CURRENT_BINARY_DIR}/abi-check-headers)
	set(ABICHECK_COMMAND abi-compliance-checker -l ${_libname} -v2 ${FULL_SO_VERSION}
		-relpath ${CMAKE_CURRENT_BINARY_DIR} -dump-abi abi-descriptor.xml
		|| cat ${CMAKE_CURRENT_BINARY_DIR}/logs/${_libname}/[0-9]*/log.txt)
	get_directory_property(INCLUDE_DIRS INCLUDE_DIRECTORIES)
	list(REMOVE_DUPLICATES INCLUDE_DIRS)
	string(REGEX REPLACE ";" "\n" INCLUDE_DIRS "${INCLUDE_DIRS}")
	configure_file(../abi-descriptor.template abi-descriptor.xml)
	# discover and substitute list of include directories for ABI compatibility
	# checks
	file(GLOB HEADERS *.h)
	file(MAKE_DIRECTORY ${ABICHECK_TMPDIR})
	file(COPY ${HEADERS} ../ws_symbol_export.h DESTINATION ${ABICHECK_TMPDIR})
	add_custom_target(dumpabi-${_libname} DEPENDS ${_libname}.abi.tar.gz)
ENDMACRO()

