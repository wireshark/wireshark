# Sets RC information on Windows.
# UNIQUE_RC - Use if the program has its own .rc.in file. Otherwise cli_template.rc.in will be used.
# EXE_NAME - The lowercase executable base name.
# PROGRAM_NAME - The program's proper, capitalized name.
# COPYRIGHT_INFO - Year followed by copyright holder names if different from default.
function(set_executable_resources EXE_NAME PROGRAM_NAME)
	if (WIN32)
		set(options UNIQUE_RC)
		set(one_value_args COPYRIGHT_INFO)
		cmake_parse_arguments(EXE_RC "${options}" "${one_value_args}" "" ${ARGN} )
		if (EXE_RC_COPYRIGHT_INFO)
			set(COPYRIGHT_INFO "${EXE_RC_COPYRIGHT_INFO}")
		else()
			# Use the original Wireshark / TShark .rc copyright.
			set(COPYRIGHT_INFO "2000 Gerald Combs <gerald@wireshark.org>, Gilbert Ramirez <gram@alumni.rice.edu> and many others")
		endif()
		set(${EXE_NAME}_FILES ${${EXE_NAME}_FILES} ${CMAKE_BINARY_DIR}/image/${EXE_NAME}.rc PARENT_SCOPE)
		if (EXE_RC_UNIQUE_RC)
			set (_in_file ${EXE_NAME})
		else()
			set (_in_file "cli_template")
		endif()
		set(ICON_PATH "${CMAKE_SOURCE_DIR}/image/")
		configure_file( ${CMAKE_SOURCE_DIR}/image/${_in_file}.rc.in ${CMAKE_BINARY_DIR}/image/${EXE_NAME}.rc @ONLY )
	endif()
endfunction()
