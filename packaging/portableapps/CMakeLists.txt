# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To do:
# - Use CPack to generate the PortableApps package.

set(PORTABLEAPPS_NAME "${CMAKE_PROJECT_NAME}Portable")
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
	set(_portableapps_app_dir "${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/${CMAKE_PROJECT_NAME}")
	file(TO_NATIVE_PATH "${_portableapps_app_dir}" _portableapps_app_dir_native)
	file(TO_NATIVE_PATH "${DATAFILE_DIR}" _datafile_dir_native)
	file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}/packaging/portableapps/xcopy-deploy-exclude.txt" _xcopy_deploy_exclude)

	add_custom_target(portableapps_app_dir
		# We "Deploy using XCopy," which is described at
		# https://msdn.microsoft.com/en-us/library/ms235291.aspx
		# We also assume that the project has been built at this point.
		COMMAND ${CMAKE_COMMAND} -E remove_directory ${_portableapps_app_dir}
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_portableapps_app_dir}
		COMMAND xcopy ${_datafile_dir_native} ${_portableapps_app_dir_native} /D /I /E /Y /exclude:${_xcopy_deploy_exclude}
	)

	set_target_properties(portableapps_app_dir PROPERTIES FOLDER "Packaging")

	if(MSVCR_DLL)
		add_custom_target(portableapps_runtime
			COMMAND xcopy "${MSVCR_DLL}" ${_portableapps_app_dir_native} /D /I /Y
		)
	else(MSVCR_DLL)
		add_custom_target(portableapps_runtime
			COMMAND ${CMAKE_COMMAND} -E echo "C Runtime MUST be installed on target system."
		)
	endif(MSVCR_DLL)

	set_target_properties(portableapps_runtime PROPERTIES FOLDER "Packaging")
	add_dependencies(portableapps_runtime portableapps_app_dir)

	# Build the PortableApps package.
	# nsis_package_prep must be built prior to this.
	set (_portableapps_package ${CMAKE_BINARY_DIR}/packaging/portableapps/WiresharkPortable_$(VERSION).exe)
	add_custom_target(portableapps_package
		DEPENDS
			portableapps_runtime
			${_portableapps_package}
	)
	set_target_properties(portableapps_package PROPERTIES FOLDER "Packaging")

	set(PORTABLEAPPS_PACKAGE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_MICRO}.0")
	configure_file(
		${CMAKE_SOURCE_DIR}/packaging/portableapps/appinfo.tmpl
		${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appinfo.ini
		NEWLINE_STYLE WIN32
	)

	foreach(_portableapps_dir ${PORTABLEAPPS_DIRS})
		add_custom_command(OUTPUT ${_portableapps_dir}
			COMMAND ${CMAKE_COMMAND} -E make_directory ${_portableapps_dir}
		)
	endforeach()

	set(_portableapps_launcher_ini ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/Launcher/${PORTABLEAPPS_NAME}.ini)
	add_custom_command(OUTPUT ${_portableapps_launcher_ini}
		DEPENDS
			${PORTABLEAPPS_DIRS}
			${CMAKE_SOURCE_DIR}/packaging/portableapps/${PORTABLEAPPS_NAME}.ini
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/packaging/portableapps/${PORTABLEAPPS_NAME}.ini ${_portableapps_launcher_ini}
	)

	set(_portableapps_launcher_exe ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/${PORTABLEAPPS_NAME}.exe)
	file(TO_NATIVE_PATH "${PORTABLEAPPS_LAUNCHER_STAGING_DIR}" _portableapps_native )
	add_custom_command(OUTPUT ${_portableapps_launcher_exe}
		DEPENDS
			${_portableapps_launcher_ini}
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/packaging/portableapps/help.html ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/help.html
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/packaging/portableapps/help.html ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/help.html
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/image/wireshark.ico ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon.ico
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/image/wsicon16.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_16.png
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/image/wsicon32.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_32.png
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/image/wsicon128.png ${PORTABLEAPPS_LAUNCHER_STAGING_DIR}/App/AppInfo/appicon_128.png
		COMMAND ${PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE} ${_portableapps_native}
	)

	add_custom_command(OUTPUT ${_portableapps_package}
		DEPENDS
			${PORTABLEAPPS_DIRS}
			${CMAKE_BINARY_DIR}/packaging/portableapps/appinfo.ini
			${_portableapps_launcher_exe}
		COMMAND ${PORTABLEAPPS_INSTALLER_EXECUTABLE} ${_portableapps_native}
	)
endmacro( ADD_PORTABLEAPPS_PACKAGE_TARGET )

#set(CLEAN_FILES
#	${_launcher_dir}
#	${_portableapps_package}
#)
