# Plugin convenience macros.

# Set information
macro(SET_MODULE_INFO _plugin _ver_major _ver_minor _ver_micro _ver_extra)
	if(WIN32)
		# Create the Windows .rc file for the plugin.
		set(MODULE_NAME ${_plugin})
		set(MODULE_VERSION_MAJOR ${_ver_major})
		set(MODULE_VERSION_MINOR ${_ver_minor})
		set(MODULE_VERSION_MICRO ${_ver_micro})
		set(MODULE_VERSION_EXTRA ${_ver_extra})
		set(MODULE_VERSION "${MODULE_VERSION_MAJOR}.${MODULE_VERSION_MINOR}.${MODULE_VERSION_MICRO}.${MODULE_VERSION_EXTRA}")
		set(RC_MODULE_VERSION "${MODULE_VERSION_MAJOR},${MODULE_VERSION_MINOR},${MODULE_VERSION_MICRO},${MODULE_VERSION_EXTRA}")

		set(MSVC_VARIANT "${CMAKE_GENERATOR}")

		# Create the plugin.rc file from the template
		if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/plugin.rc.in)
			set(_plugin_rc_in ${CMAKE_CURRENT_SOURCE_DIR}/plugin.rc.in)
		else()
			set(_plugin_rc_in ${CMAKE_SOURCE_DIR}/plugins/plugin.rc.in)
		endif()
		configure_file(${_plugin_rc_in} plugin.rc @ONLY)
		set(PLUGIN_RC_FILE ${CMAKE_CURRENT_BINARY_DIR}/plugin.rc)
	endif()

	set(PLUGIN_VERSION "${_ver_major}.${_ver_minor}.${_ver_micro}")
	add_definitions(-DPLUGIN_VERSION=\"${PLUGIN_VERSION}\")
endmacro()

macro(ADD_WIRESHARK_PLUGIN_LIBRARY _plugin _subfolder)
	add_library(${_plugin} MODULE
		${PLUGIN_FILES}
		${PLUGIN_RC_FILE}
	)

	target_include_directories(${_plugin} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

	set_target_properties(${_plugin} PROPERTIES
		PREFIX ""
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Plugins"
	)
	if(MSVC)
		set_target_properties(${_plugin} PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
	endif()

	set_target_properties(${_plugin} PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${PLUGIN_DIR}/${_subfolder}
		INSTALL_RPATH ""
	)

	add_dependencies(plugins ${_plugin})
endmacro()

macro(ADD_PLUGIN_LIBRARY _plugin _subfolder)
	message(WARNING "${CMAKE_PARENT_LIST_FILE}: add_plugin_library is deprecated. Use add_wireshark_plugin_library instead.")
	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} ${_subfolder})
endmacro()

macro(ADD_LOGRAY_PLUGIN_LIBRARY _plugin _subfolder)
	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} ${_subfolder})

	set_target_properties(${_plugin} PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${LOGRAY_PLUGIN_DIR}/${_subfolder}
	)
endmacro()

macro(INSTALL_PLUGIN _plugin _subfolder)
	install(TARGETS ${_plugin}
		LIBRARY DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}/${_subfolder} NAMELINK_SKIP
		RUNTIME DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}
		ARCHIVE DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}
)
endmacro()
