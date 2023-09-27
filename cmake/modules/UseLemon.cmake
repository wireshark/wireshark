#

find_program(LEMON_EXECUTABLE lemon)

if(LEMON_EXECUTABLE)
	# Use system lemon
	macro(generate_lemon_file _out _in)
		add_custom_command(
			OUTPUT
				${_out}.c
				# These files are generated as side-effect
				${_out}.h
				${_out}.out
			COMMAND ${LEMON_EXECUTABLE}
				-T/usr/share/lemon/lempar.c
				-d.
				${_in}
			DEPENDS
				${_in}
		)
	endmacro()
	add_custom_target(lemon)
else()
	# Compile bundled lemon with support for -- to end options
	macro(generate_lemon_file _out _in)
		add_custom_command(
			OUTPUT
				${_out}.c
				# These files are generated as side-effect
				${_out}.h
				${_out}.out
			COMMAND $<TARGET_FILE:lemon>
				-T${CMAKE_SOURCE_DIR}/tools/lemon/lempar.c
				-d.
				--
				${_in}
			DEPENDS
				${_in}
				lemon
				${CMAKE_SOURCE_DIR}/tools/lemon/lempar.c
		)
	endmacro()
endif()

macro(ADD_LEMON_FILES _source _generated)

	foreach (_current_FILE ${ARGN})
		get_filename_component(_in ${_current_FILE} ABSOLUTE)
		get_filename_component(_basename ${_current_FILE} NAME_WE)

		set(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename})

		generate_lemon_file(${_out} ${_in})

		list(APPEND ${_source} ${_in})
		list(APPEND ${_generated} ${_out}.c)

		if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
			set_source_files_properties(${_out}.c PROPERTIES COMPILE_OPTIONS "/w")
		elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
			set_source_files_properties(${_out}.c PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter")
		else()
			# Build with some warnings for lemon generated code
		endif()
	endforeach(_current_FILE)
endmacro(ADD_LEMON_FILES)
