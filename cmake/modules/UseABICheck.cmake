#
# ABI Check related macros
#
# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12

MACRO(ABICHECK _libname)
	get_directory_property(INCLUDE_DIRS INCLUDE_DIRECTORIES)
	list(REMOVE_DUPLICATES INCLUDE_DIRS)
	string(REGEX REPLACE ";" "\n" INCLUDE_DIRS "${INCLUDE_DIRS}")
	configure_file(../abi-descriptor.template abi-descriptor.xml)
	# discover and substitute list of include directories for ABI compatibility
	# checks
	file(GLOB HEADERS *.h)
	file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/abi-check-headers)
	file(COPY ${HEADERS} ../ws_symbol_export.h DESTINATION abi-check-headers)
	add_custom_target(dumpabi-${_libname} DEPENDS ${_libname}.abi.tar.gz)
ENDMACRO()

