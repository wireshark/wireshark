# Plugin convenience macros.

# Set information
macro(SET_MODULE_INFO _plugin _ver_major _ver_minor _ver_micro _ver_extra)
	# Create the Windows .rc file for the plugin.
	# The values come from several files in the source, I can't see how to reuse them

	set(PACKAGE ${_plugin})
	set(MODULE_VERSION_MAJOR ${_ver_major})
	set(MODULE_VERSION_MINOR ${_ver_minor})
	set(MODULE_VERSION_MICRO ${_ver_micro})
	set(MODULE_VERSION_EXTRA ${_ver_extra})
	set(MODULE_VERSION "${MODULE_VERSION_MAJOR}.${MODULE_VERSION_MINOR}.${MODULE_VERSION_MICRO}.${MODULE_VERSION_EXTRA}")
	set(RC_MODULE_VERSION "${MODULE_VERSION_MAJOR},${MODULE_VERSION_MINOR},${MODULE_VERSION_MICRO},${MODULE_VERSION_EXTRA}")

	# This info is from Makefile.am
	set(PLUGIN_NAME ${PACKAGE})

	set(MSVC_VARIANT "${CMAKE_GENERATOR}")

	# The rc.in requires a plain VERSION variable
	set(VERSION ${PROJECT_VERSION})

	# Create the plugin.rc file from the template
	configure_file(plugin.rc.in plugin.rc @ONLY)
endmacro()

macro(ADD_PLUGIN_LIBRARY _plugin)
	add_library(${_plugin} ${LINK_MODE_MODULE}
		${PLUGIN_FILES}
		${CMAKE_CURRENT_BINARY_DIR}/plugin.rc
	)

	set_target_properties(${_plugin} PROPERTIES
		PREFIX ""
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Plugins"
	)

	# LIBRARY_OUTPUT_DIRECTORY alone appears to be sufficient.
	set_target_properties(${_plugin} PROPERTIES
		#ARCHIVE_OUTPUT_DIRECTORY ${PLUGIN_DIR}
		LIBRARY_OUTPUT_DIRECTORY ${PLUGIN_DIR}
		#RUNTIME_OUTPUT_DIRECTORY ${PLUGIN_DIR}
	)

	# Try to force output to ${PLUGIN_DIR} without the configuration
	# type appended. Needed for CPack on Windows.
	foreach(_config_type ${CMAKE_CONFIGURATION_TYPES})
		string(TOUPPER ${_config_type} _config_upper)
		set_target_properties(${_plugin} PROPERTIES
			LIBRARY_OUTPUT_DIRECTORY_${_config_upper} ${CMAKE_BINARY_DIR}/run/${_config_type}/plugins
		)
	endforeach()

	target_link_libraries(${_plugin} epan)
	add_dependencies(plugins ${_plugin})
endmacro()
