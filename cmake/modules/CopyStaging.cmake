#
# Add a custom target to copy support files to our staging directory.
#
# add_staging_target(Name
#                    [DEST dir]
#                    [DEPENDS target1 [target2 ...]]
#                    FILES file1 [file2 ...])
#

function(add_staging_target TARGET_NAME)
	cmake_parse_arguments(_ARG "" "DEST" "DEPENDS;FILES" ${ARGN})

	foreach(_input_file ${_ARG_FILES})
		get_filename_component(_file_basename "${_input_file}" NAME)
		if(_ARG_DEST)
			set(_dest_dir "${_ARG_DEST}")
		else()
			set(_dest_dir "${CMAKE_BINARY_DIR}/run")
		endif()
		set(_output_file "${_dest_dir}/${_file_basename}")
		add_custom_command(OUTPUT "${_output_file}"
			COMMAND ${CMAKE_COMMAND} -E make_directory
				"${_dest_dir}"
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${_input_file}"
				"${_output_file}"
			DEPENDS
				"${_input_file}"
		)
		list(APPEND _files_depends "${_output_file}")
	endforeach()

	add_custom_target(${TARGET_NAME} ALL DEPENDS ${_files_depends})
	if(_ARG_DEPENDS)
		add_dependencies(${TARGET_NAME} ${_ARG_DEPENDS})
	endif()
endfunction()
