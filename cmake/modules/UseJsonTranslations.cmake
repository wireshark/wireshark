# UseJsonTranslations.cmake — Generate C++ translation marker files from JSON data
#
# GENERATE_JSON_TR_STRINGS(
#   INPUT       <path to input .json file>
#   OUTPUT      <path to output .cpp file>
#   CONTEXT     <Qt translation context class name>
#   EXTRACT     <array:field1,field2,...> [...]
# )
#
# Creates an add_custom_command that runs generate_json_translations.py to
# produce a #if 0 C++ file with QT_TRANSLATE_NOOP() markers for lupdate.
#
# SPDX-License-Identifier: GPL-2.0-or-later

function(GENERATE_JSON_TR_STRINGS)
	cmake_parse_arguments(
		_arg
		""                       # options (boolean flags)
		"INPUT;OUTPUT;CONTEXT"   # one-value keywords
		"EXTRACT"                # multi-value keywords
		${ARGN}
	)

	if(NOT _arg_INPUT)
		message(FATAL_ERROR "GENERATE_JSON_TR_STRINGS: INPUT is required")
	endif()
	if(NOT _arg_OUTPUT)
		message(FATAL_ERROR "GENERATE_JSON_TR_STRINGS: OUTPUT is required")
	endif()
	if(NOT _arg_CONTEXT)
		message(FATAL_ERROR "GENERATE_JSON_TR_STRINGS: CONTEXT is required")
	endif()
	if(NOT _arg_EXTRACT)
		message(FATAL_ERROR "GENERATE_JSON_TR_STRINGS: at least one EXTRACT spec is required")
	endif()

	set(_extract_args)
	foreach(_spec IN LISTS _arg_EXTRACT)
		list(APPEND _extract_args --extract ${_spec})
	endforeach()

	add_custom_command(
		OUTPUT ${_arg_OUTPUT}
		COMMAND ${Python3_EXECUTABLE}
			${CMAKE_SOURCE_DIR}/tools/generate_json_translations.py
			${_arg_INPUT}
			${_arg_OUTPUT}
			${_arg_CONTEXT}
			${_extract_args}
		DEPENDS
			${_arg_INPUT}
			${CMAKE_SOURCE_DIR}/tools/generate_json_translations.py
		COMMENT "Generating translation strings from ${_arg_INPUT} for lupdate"
	)
endfunction()
