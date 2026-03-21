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
		LIBRARY_OUTPUT_DIRECTORY ${WIRESHARK_PLUGIN_DIR}/${_subfolder}
		INSTALL_RPATH ""
	)

	add_dependencies(plugins ${_plugin})
endmacro()

macro(INSTALL_PLUGIN _plugin _subfolder)
	install(TARGETS ${_plugin}
		LIBRARY DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}/${_subfolder} NAMELINK_SKIP
		RUNTIME DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}
		ARCHIVE DESTINATION ${PLUGIN_INSTALL_VERSION_LIBDIR}
)
endmacro()

######################################################################################################
# Plugin type specific macros.  They handle a little more than the basic add_wireshark_plugin_library
######################################################################################################

# add_wireshark_epan_plugin_library()
#
# Macro used for dissector plugins. Handles most common cases as long as a few variables are set (see below)
#
# @param _plugin Name of the plugin
# @param PLUGIN_LIBS (Optional) List of additional libraries to link against (beyond the required epan library)
# @param PLUGIN_INCS (Optional) List of additional include directories to use when compiling the plugin (beyond the required epan include directory)
#
# Required variables that must be set before calling the macro:
# DISSECTOR_SRC - List of source files that are part of the dissector plugin
#
# Optional variables that can be set before calling the macro:
# DISSECTOR_SUPPORT_SRC - List of source files that are part of the dissector plugin but are not themselves dissectors.  This is just for organizational purposes and has no effect on the build.
# PLUGIN_FILES - List of all source files that are part of the plugin.  If this is not set, it will default to the combination of DISSECTOR_SRC and DISSECTOR_SUPPORT_SRC plus plugin.c
# DISSECTOR_HEADERS - List of header files that are part of the dissector plugin.  This is only used for the CheckAPI() call.  If this is not set, it will default to all .h files in the plugin source directory.
macro(ADD_WIRESHARK_EPAN_PLUGIN_LIBRARY _plugin)

	set(multiValueArgs PLUGIN_LIBS PLUGIN_INCS)
	cmake_parse_arguments(ARG "" "" "${multiValueArgs}" ${ARGN})

	#Provide the default PLUGIN_FILES if the caller didn't specify it.
	if(NOT DEFINED PLUGIN_FILES)
		set(PLUGIN_FILES
			plugin.c
			${DISSECTOR_SRC}
			${DISSECTOR_SUPPORT_SRC}

		)
	endif()

	set_source_files_properties(
		${PLUGIN_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
	)

	register_plugin_files(plugin.c
		plugin
		${DISSECTOR_SRC}
		${DISSECTOR_SUPPORT_SRC}
	)

	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} epan)

	target_include_directories(${_plugin}
					SYSTEM PRIVATE ${ARG_PLUGIN_INCS}
	)
	target_link_libraries(${_plugin} epan ${ARG_PLUGIN_LIBS})

	INSTALL_PLUGIN(${_plugin} epan)

	#This is more about potentially overriding the CheckAPI behavior than redefining the DISSECTOR_HEADERS variable.
	#If the caller has defined DISSECTOR_HEADERS, then we assume they know what they are doing and won't try to
	#"help" by globbing for .h files in the plugin source directory.
	if(NOT DEFINED DISSECTOR_HEADERS)
		file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
		CHECKAPI(
			NAME ${_plugin}
			SWITCHES
				--group dissectors-prohibited
				--group dissectors-restricted
			SOURCES
				${DISSECTOR_SRC}
				${DISSECTOR_SUPPORT_SRC}
				${DISSECTOR_HEADERS}
		)
	endif()
endmacro()

# add_wireshark_tap_plugin_library()
#
# Macro used for tap plugins. Handles most common cases as long as a few variables are set (see below)
#
# @param _plugin Name of the plugin
# @param PLUGIN_LIBS (Optional) List of additional libraries to link against (beyond the required epan library)
# @param PLUGIN_INCS (Optional) List of additional include directories to use when compiling the plugin (beyond the required epan include directory)
#
# Required variables that must be set before calling the macro:
# TAP_SRC - List of source files that are part of the tap plugin
macro(ADD_WIRESHARK_TAP_PLUGIN_LIBRARY _plugin)

	set(multiValueArgs PLUGIN_LIBS PLUGIN_INCS)

	cmake_parse_arguments(ARG "" "" "${multiValueArgs}" ${ARGN})

	set(PLUGIN_FILES
		plugin.c
		${TAP_SRC}
	)

	set_source_files_properties(
		${PLUGIN_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
	)

	register_plugin_files(plugin.c
		plugin_tap
		${TAP_SRC}
	)

	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} epan)

	target_include_directories(${_plugin}
					SYSTEM PRIVATE ${ARG_PLUGIN_INCS}
	)
	target_link_libraries(${_plugin} epan ${ARG_PLUGIN_LIBS})

	INSTALL_PLUGIN(${_plugin} epan)

	file(GLOB TAP_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
	CHECKAPI(
		NAME ${_plugin}
		SWITCHES
		SOURCES
			${TAP_SRC}
			${TAP_HEADERS}
	)
endmacro()

# add_wireshark_codec_plugin_library()
#
# Macro used for codec plugins. Handles most common cases as long as a few variables are set (see below)
#
# @param _plugin Name of the plugin
# @param PLUGIN_LIBS (Optional) List of additional libraries to link against (beyond the required codec library)
# @param PLUGIN_INCS (Optional) List of additional include directories to use when compiling the plugin (beyond the required codecs include directory)
#
# Required variables that must be set before calling the macro:
# CODEC_SRC - List of source files that are part of the codec plugin
#
# Optional variables that can be set before calling the macro:
# CODEC_HEADERS - List of header files that are part of the codec plugin.  This is only used for the CheckAPI() call.  If this is not set, it will default to all .h files in the plugin source directory.
macro(ADD_WIRESHARK_CODEC_PLUGIN_LIBRARY _plugin)

	set(multiValueArgs PLUGIN_LIBS PLUGIN_INCS)

	cmake_parse_arguments(ARG "" "" "${multiValueArgs}" ${ARGN})

	set(PLUGIN_FILES
		plugin.c
		${CODEC_SRC}
	)

	set_source_files_properties(
		${PLUGIN_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
	)

	register_plugin_files(plugin.c
		plugin_codec
		${CODEC_SRC}
	)

	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} codecs)

	target_include_directories(${_plugin} PRIVATE ${CMAKE_SOURCE_DIR}/codecs)

	target_link_libraries(${_plugin} wsutil ${ARG_PLUGIN_LIBS})

	if (ARG_PLUGIN_INCS)
		target_include_directories(${_plugin} SYSTEM PRIVATE ${ARG_PLUGIN_INCS})
	endif()

	INSTALL_PLUGIN(${_plugin} codecs)

	if(NOT DEFINED CODEC_HEADERS)
		file(GLOB CODEC_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
	endif()
	CHECKAPI(
		NAME
			${_plugin}
		SWITCHES
		SOURCES
			${CODEC_SRC}
			${CODEC_HEADERS}
)
endmacro()

# add_wireshark_wiretap_plugin_library()
#
# Macro used for wiretap (file) plugins. Handles most common cases as long as a few variables are set (see below)
#
# @param _plugin Name of the plugin
# @param PLUGIN_LIBS (Optional) List of additional libraries to link against (beyond the required wiretap library)
# @param PLUGIN_INCS (Optional) List of additional include directories to use when compiling the plugin (beyond the required wiretap include directory)
#
# Required variables that must be set before calling the macro:
# WIRETAP_SRC - List of source files that are part of the tap plugin
macro(ADD_WIRESHARK_WIRETAP_PLUGIN_LIBRARY _plugin)

	set(multiValueArgs PLUGIN_LIBS PLUGIN_INCS)

	cmake_parse_arguments(ARG "" "" "${multiValueArgs}" ${ARGN})

	set(PLUGIN_FILES
		plugin.c
		${WIRETAP_SRC}
	)

	set_source_files_properties(
		${PLUGIN_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
	)

	register_plugin_files(plugin.c
		plugin_wtap
		${WIRETAP_SRC}
	)

	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} wiretap)

	target_include_directories(${_plugin}
					PRIVATE ${CMAKE_SOURCE_DIR}/wiretap
					SYSTEM PRIVATE ${ARG_PLUGIN_INCS}
	)

	target_link_libraries(${_plugin} wiretap ${ARG_PLUGIN_LIBS})

	INSTALL_PLUGIN(${_plugin} wiretap)

	file(GLOB WIRETAP_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
	CHECKAPI(
		NAME
			${_plugin}
		SWITCHES
		SOURCES
			${WIRETAP_SRC}
			${WIRETAP_HEADERS}
	)
endmacro()

macro(ADD_PLUGIN_LIBRARY _plugin _subfolder)
	message(WARNING "${CMAKE_PARENT_LIST_FILE}: add_plugin_library is deprecated. Use add_wireshark_plugin_<type>_library instead.")
	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} ${_subfolder})
endmacro()

macro(ADD_STRATOSHARK_PLUGIN_LIBRARY _plugin _subfolder)
	ADD_WIRESHARK_PLUGIN_LIBRARY(${_plugin} ${_subfolder})

	set_target_properties(${_plugin} PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${STRATOSHARK_PLUGIN_DIR}/${_subfolder}
	)
endmacro()

