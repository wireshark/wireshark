# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# PortableApps.com appears to use "FooAppPortable" for 32-bit packages
# and "FooAppPortable64" for 64-bit packages. We deviate from that here
# by always appending a bit suffix.
#
# PA.com also tends to ship 32-bit and 64-bit executables in combined
# packages. We don't do that because a) we're large and b) we build
# our 32-bit and 64-bit packages independently in separate pipelines.

if(WIRESHARK_TARGET_PLATFORM STREQUAL "win64")
	set(PORTABLEAPPS_BITS 64)
else()
	message(FATAL_ERROR "Your mysterious moon-man architecture \"${WIRESHARK_TARGET_PLATFORM}\" frightens and confuses us.")
endif()
set(PORTABLEAPPS_BITS ${PORTABLEAPPS_BITS} PARENT_SCOPE)

set(PORTABLEAPPS_NAME "${CMAKE_PROJECT_NAME}Portable${PORTABLEAPPS_BITS}")
set(PORTABLEAPPS_NAME ${PORTABLEAPPS_NAME} PARENT_SCOPE)

set (_launcher_dir "${CMAKE_CURRENT_BINARY_DIR}/${PORTABLEAPPS_NAME}")
set (PORTABLEAPPS_LAUNCHER_STAGING_DIR ${_launcher_dir} PARENT_SCOPE)

set(PORTABLEAPPS_DIRS
	${_launcher_dir}
	${_launcher_dir}/App
	${_launcher_dir}/App/AppInfo
	${_launcher_dir}/App/AppInfo/Launcher
	${_launcher_dir}/Data
	${_launcher_dir}/Other
	${_launcher_dir}/Other/Source
	PARENT_SCOPE
)

macro( ADD_PORTABLEAPPS_PACKAGE_TARGET )
	# Copy our binaries, libraries, and data files to the PortableApps build directory.
	set(_wireshark_portableapps_app_dir "${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/${CMAKE_PROJECT_NAME}")
	file(TO_NATIVE_PATH "${_wireshark_portableapps_app_dir}" _wireshark_portableapps_app_dir_native)
	file(TO_NATIVE_PATH "${DATAFILE_DIR}" _datafile_dir_native)
	file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}/packaging/portableapps/xcopy-deploy-exclude.txt" _xcopy_deploy_exclude)

	add_custom_target(wireshark_portableapps_app_dir
		# We "Deploy using XCopy," which is described at
		# https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2008/ms235291(v=vs.90)
		# We also assume that the project has been built at this point.
		COMMAND ${CMAKE_COMMAND} -E remove_directory ${_wireshark_portableapps_app_dir}
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_wireshark_portableapps_app_dir}
		COMMAND xcopy ${_datafile_dir_native} ${_wireshark_portableapps_app_dir_native} /D /I /E /Y /exclude:${_xcopy_deploy_exclude}
	)

	set_target_properties(wireshark_portableapps_app_dir PROPERTIES
		FOLDER "Packaging"
		EXCLUDE_FROM_DEFAULT_BUILD True
	)

	if(MSVCR_DLL)
		add_custom_target(wireshark_portableapps_runtime
			COMMAND xcopy "${MSVCR_DLL}" ${_wireshark_portableapps_app_dir_native} /D /I /Y
		)
	else(MSVCR_DLL)
		add_custom_target(wireshark_portableapps_runtime
			COMMAND ${CMAKE_COMMAND} -E echo "C Runtime MUST be installed on target system."
		)
	endif(MSVCR_DLL)

	set_target_properties(wireshark_portableapps_runtime PROPERTIES
		FOLDER "Packaging"
		EXCLUDE_FROM_DEFAULT_BUILD True
	)
	add_dependencies(wireshark_portableapps_runtime wireshark_portableapps_app_dir)

	# Build the PortableApps package.
	# wireshark_nsis_prep must be built prior to this.
	# XXX Rename this to wireshark_portableapps
	set (_portableapps_package ${CMAKE_BINARY_DIR}/packaging/portableapps/${PORTABLEAPPS_NAME}_${PROJECT_VERSION}.paf.exe)
	add_custom_target(wireshark_portableapps
		DEPENDS
			wireshark_portableapps_runtime
			${_portableapps_package}
	)
	set_target_properties(wireshark_portableapps PROPERTIES
		FOLDER "Packaging"
		EXCLUDE_FROM_DEFAULT_BUILD True
	)

	set(PORTABLEAPPS_PACKAGE_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}.0")
	configure_file(
		${CMAKE_SOURCE_DIR}/packaging/portableapps/appinfo.tmpl
		${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appinfo.ini
		NEWLINE_STYLE WIN32
	)

	foreach(_portableapps_dir ${PORTABLEAPPS_DIRS})
		file(MAKE_DIRECTORY ${_portableapps_dir})
	endforeach()

	set(_portableapps_launcher_ini ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/Launcher/${PORTABLEAPPS_NAME}.ini)
	configure_file(
		${CMAKE_SOURCE_DIR}/packaging/portableapps/${CMAKE_PROJECT_NAME}Portable.tmpl
		${_portableapps_launcher_ini}
		NEWLINE_STYLE WIN32
	)

	set(_portableapps_launcher_exe ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/${PORTABLEAPPS_NAME}.exe)
	file(TO_NATIVE_PATH "${PORTABLEAPPS_LAUNCHER_STAGING_DIR}" _portableapps_native )
	add_custom_command(OUTPUT ${_portableapps_launcher_exe}
		DEPENDS
			${_portableapps_launcher_ini}
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/packaging/portableapps/help.html ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/help.html
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/packaging/portableapps/help.html ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/help.html
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/resources/icons/wireshark.ico ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon.ico
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/resources/icons/wsicon16.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_16.png
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/resources/icons/wsicon32.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_32.png
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/resources/icons/wsicon128.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_128.png
		COMMAND ${PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE} ${_portableapps_native}
	)

	add_custom_command(OUTPUT ${_portableapps_package}
		DEPENDS
			${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appinfo.ini
			${_portableapps_launcher_ini}
			${_portableapps_launcher_exe}
		COMMAND ${PORTABLEAPPS_INSTALLER_EXECUTABLE} ${_portableapps_native}
	)
endmacro( ADD_PORTABLEAPPS_PACKAGE_TARGET )

#set(CLEAN_FILES
#	${_launcher_dir}
#	${_portableapps_package}
#)
