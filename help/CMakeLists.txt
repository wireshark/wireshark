
set(copy_help_files_depends)

set(HELP_FILES ${CMAKE_CURRENT_SOURCE_DIR}/toc)

set(_textify_help_files
	capture_filters.txt
	capturing.txt
	display_filters.txt
	getting_started.txt
	overview.txt
)

foreach(_file ${_textify_help_files})
	if(WIN32)
		list(APPEND HELP_FILES ${CMAKE_CURRENT_BINARY_DIR}/${_file})
	else()
		list(APPEND HELP_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${_file})
	endif()
endforeach()

list(APPEND HELP_FILES ${CMAKE_CURRENT_BINARY_DIR}/faq.txt)

if(WIN32)
	foreach(_help_file ${_textify_help_files})
		file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}" _help_dest_dir)
		add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${_help_file}"
			COMMAND ${POWERSHELL_COMMAND} "${CMAKE_SOURCE_DIR}/tools/textify.ps1"
				-Destination "${_help_dest_dir}"
				"${CMAKE_CURRENT_SOURCE_DIR}/${_help_file}"
			DEPENDS
				"${CMAKE_CURRENT_SOURCE_DIR}/${_help_file}"
		)
	endforeach()
endif()

# Create help/faq.txt when missing
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/faq.txt"
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/faq.py -b > faq.tmp.html
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/html2text.py
		faq.tmp.html > "${CMAKE_CURRENT_BINARY_DIR}/faq.txt"
	COMMAND ${CMAKE_COMMAND} -E remove faq.tmp.html
	DEPENDS
		"${CMAKE_CURRENT_SOURCE_DIR}/faq.py"
		"${CMAKE_SOURCE_DIR}/tools/html2text.py"
)

foreach(_help_file ${HELP_FILES})
	get_filename_component(_name ${_help_file} NAME)
	set(_src_file ${_help_file})
	set(_dst_file "${DATAFILE_DIR}/help/${_name}")
	add_custom_command(OUTPUT "${_dst_file}"
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${_src_file}"
			"${_dst_file}"
		DEPENDS
			"${_src_file}"
	)
	list(APPEND copy_help_files_depends "${_dst_file}")
endforeach()

add_custom_target(copy_help_files ALL DEPENDS ${copy_help_files_depends} )
set_target_properties(copy_help_files PROPERTIES FOLDER "Copy Tasks")

install(FILES ${HELP_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/help")
