# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# We should use CPack to generate the NSIS package. Even better,
# we should use CPack to create a .msi using WiX.

set(WIRESHARK_NSIS_GENERATED_FILES
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-manifest.nsh
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-config.nsh
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-qt-manifest.nsh
)
set(WIRESHARK_NSIS_GENERATED_FILES ${WIRESHARK_NSIS_GENERATED_FILES} PARENT_SCOPE)

set(WIRESHARK_NSIS_FILES
	wireshark.nsi
	uninstall-wireshark.nsi
	wireshark-common.nsh
	GetWindowsVersion.nsh
	servicelib.nsh
	AdditionalTasksPage.ini
	NpcapPage.ini
	USBPcapPage.ini
	${WIRESHARK_NSIS_GENERATED_FILES}
	PARENT_SCOPE
)

set(LOGRAY_NSIS_GENERATED_FILES
	${CMAKE_CURRENT_BINARY_DIR}/logray-manifest.nsh
	${CMAKE_CURRENT_BINARY_DIR}/logray-config.nsh
	${CMAKE_CURRENT_BINARY_DIR}/logray-qt-manifest.nsh
)
set(LOGRAY_NSIS_GENERATED_FILES ${LOGRAY_NSIS_GENERATED_FILES} PARENT_SCOPE)

set(LOGRAY_NSIS_FILES
	logray.nsi
	uninstall-logray.nsi
	logray-common.nsh
	GetWindowsVersion.nsh
	servicelib.nsh
	AdditionalTasksPage.ini
	NpcapPage.ini
	USBPcapPage.ini
	${LOGRAY_NSIS_GENERATED_FILES}
	PARENT_SCOPE
)

# Variables required for config.nsh
set(PROGRAM_NAME ${CMAKE_PROJECT_NAME})
set(LOG_PROGRAM_NAME ${LOG_PROJECT_NAME})
file(TO_NATIVE_PATH "${CMAKE_SOURCE_DIR}" TOP_SRC_DIR)
# STAGING_DIR depends on the build configuration so we pass it
# on the command line below.
file(TO_NATIVE_PATH "${CMAKE_BINARY_DIR}/docbook" DOCBOOK_DIR)
if(WIRESHARK_TARGET_PLATFORM STREQUAL "win32")
        set(TARGET_MACHINE x86)
elseif(WIRESHARK_TARGET_PLATFORM STREQUAL "win64")
        set(TARGET_MACHINE x64)
else()
        message(FATAL_ERROR "Your mysterious moon-man architecture \"${WIRESHARK_TARGET_PLATFORM}\" frightens and confuses us.")
endif()
set (MMDBRESOLVE_EXE ${MAXMINDDB_FOUND})

# Must match ${EXTRA_INSTALLER_DIR}/Npcap-X.Y.Z.exe
set(NPCAP_PACKAGE_VERSION "1.60")

set(USBPCAP_PACKAGE_VERSION "1.5.4.0")

# To do:
# - Sync the various version names between CMake and NSIS.
# - Set CMakeLists.txt version strings in tools/make-version.py
# - Add a VERSION_EXTRA cmake option
set (PRODUCT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}.${PROJECT_BUILD_VERSION})
set (LOG_PRODUCT_VERSION ${LOG_PROJECT_MAJOR_VERSION}.${LOG_PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}.${PROJECT_BUILD_VERSION})

#add_custom_target(build_nsis_package
#	DEPENDS
#		wireshark-$(WIRESHARK_TARGET_PLATFORM)-$(VERSION).exe
#)

if((BUILD_wireshark OR BUILD_logray) AND QT_FOUND)
	set (QT_DIR "\${STAGING_DIR}")
endif()

# Look for the Visual C++ Redistributable packages in the following locations:
# - _PROJECT_LIB_DIR
# - _PROJECT_LIB_DIR/vcredist_MSVCxx
# - %VCINSTALLDIR%
# - %VCINSTALLDIR%/redist/1033 (<= Visual Studio 2015)
# - %VCINSTALLDIR%/Redist/MSVC/* (>= Visual Studio 2017)
# MSVC_VERSION (_MSC_VER) = Visual Studio Version / MSVC Toolset Version
# 1900 = VS2015 14.0        / 14.00
# 1910 = VS2017 15.1, 15.2  / 14.10
# 1911 = VS2017 15.3, 15.4  / 14.11
# 1912 = VS2017 15.5        / 14.12
# 1913 = VS2017 15.6        / 14.13
# 1914 = VS2017 15.7        / 14.14
if(MSVC_VERSION GREATER_EQUAL 1930)
	set(_ws_vcredist_subdir "vcredist_MSVC2022")
elseif(MSVC_VERSION GREATER_EQUAL 1920)
	set(_ws_vcredist_subdir "vcredist_MSVC2019")
	set(_msvs_version 15.0) # Doesn't appear to be set
elseif(MSVC_VERSION GREATER_EQUAL 1910)
	set(_ws_vcredist_subdir "vcredist_MSVC2017")
	set(_msvs_version 15.0)
elseif(MSVC_VERSION GREATER_EQUAL 1900)
	set(_ws_vcredist_subdir "vcredist_MSVC2015")
	set(_ms_vcredist_subdir "redist/1033")
	set(_msvs_version 14.0)
endif()

# Try to find the Redist folder in VCINSTALLDIR which is set by vcvarsall.bat.
# If it is not set, query it within the registry. VS2015 looks for the "VC7" key
# in two locations (four if you count HKCU instead of HKLM). However, VS2017
# does not use "VC7" (it sets a directory relative to vsdevcmd_start.bat). As
# both versions do set "VS7", use that instead.
find_path(VCINSTALLDIR Redist PATHS
	"$ENV{VCINSTALLDIR}"
	"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7;${_msvs_version}]\\VC"
	"[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\VisualStudio\\SxS\\VS7;${_msvs_version}]\\VC"
	NO_DEFAULT_PATH
)
file(TO_NATIVE_PATH "${VCINSTALLDIR}" VCINSTALLDIR_NATIVE)
message(STATUS "Using VCINSTALLDIR: ${VCINSTALLDIR_NATIVE}")

# Visual Studio Community 2017 version 15.7.5 uses VCRT 14.14.26405, but an
# earlier version used 14.10.25008. Let's just glob for the right value.
if(MSVC_VERSION GREATER_EQUAL 1910 AND VCINSTALLDIR)
	file(GLOB _ms_vcredist_subdir RELATIVE "${VCINSTALLDIR}"
		"${VCINSTALLDIR}/Redist/MSVC/14.*.*")
endif()

find_program(_vcredist
	NAMES
		"vc_redist.${TARGET_MACHINE}.exe" # Visual Studio 2022 and later
		"vcredist_${TARGET_MACHINE}.exe" # Visual Studio 2019 and earlier
	PATHS "${_PROJECT_LIB_DIR}" $ENV{VCToolsRedistDir} "${VCINSTALLDIR}"
	PATH_SUFFIXES ${_ws_vcredist_subdir} ${_ms_vcredist_subdir}
	NO_DEFAULT_PATH
)
if(_vcredist)
	file(TO_NATIVE_PATH "${_vcredist}" _vcredist)
	message(STATUS "Using ${_vcredist} for the NSIS installer.")
	get_filename_component(VCREDIST_DIR ${_vcredist} DIRECTORY)
	get_filename_component(VCREDIST_EXE ${_vcredist} NAME)
endif()

if (BUILD_wireshark)
	# Ideally we would generate this at compile time using a separate cmake
	# module, e.g. cmake/modules/configure_nsis_file.cmake. However we would
	# have to figure out a clean way to pass in the variables above.
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/wireshark-config.nsh.in" _config_nsh_contents)
	string(CONFIGURE "${_config_nsh_contents}" _config_nsh_contents)
	string(REPLACE "#define" "!define" _config_nsh_contents "${_config_nsh_contents}")
	string(REPLACE "#undef" "!undef" _config_nsh_contents "${_config_nsh_contents}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wireshark-config.nsh" "${_config_nsh_contents}")

	# wireshark-manifest.nsh. Can be created at configure time.
	set(_all_manifest "${CMAKE_CURRENT_BINARY_DIR}/wireshark-manifest.nsh")
	set(_all_manifest_contents "# Files required for all sections. Generated by CMake.\n")
	set(_all_manifest_contents "${_all_manifest_contents}!ifdef BUNDLE_DEBUG_DLLS\n")
	foreach(_dll ${GLIB2_DLLS_DEBUG})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!else\n")
	foreach(_dll ${GLIB2_DLLS_RELEASE})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!endif\n")
	foreach(_dll ${CARES_DLL} ${PCRE2_DLL} ${GCRYPT_DLLS}
			${GNUTLS_DLLS} ${KERBEROS_DLLS} ${LIBSSH_DLLS} ${LUA_DLL}
			${LZ4_DLL} ${NGHTTP2_DLL} ${SBC_DLL} ${SMI_DLL} ${SNAPPY_DLL}
			${SPANDSP_DLL} ${BCG729_DLL} ${LIBXML2_DLLS} ${WINSPARKLE_DLL}
			${ZLIB_DLL} ${BROTLI_DLLS} ${ZSTD_DLL} ${ILBC_DLL} ${OPUS_DLL}
			# Needed for mmdbresolve
			${MAXMINDDB_DLL}
		)
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	foreach(_script "init.lua" "console.lua" "dtd_gen.lua")
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_script}\"\n")
	endforeach()
	file(WRITE "${_all_manifest}" "${_all_manifest_contents}")
endif()

if (BUILD_logray)
	# Ideally we would generate this at compile time using a separate cmake
	# module, e.g. cmake/modules/configure_nsis_file.cmake. However we would
	# have to figure out a clean way to pass in the variables above.
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/logray-config.nsh.in" _config_nsh_contents)
	string(CONFIGURE "${_config_nsh_contents}" _config_nsh_contents)
	string(REPLACE "#define" "!define" _config_nsh_contents "${_config_nsh_contents}")
	string(REPLACE "#undef" "!undef" _config_nsh_contents "${_config_nsh_contents}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/logray-config.nsh" "${_config_nsh_contents}")

	# logray-manifest.nsh. Can be created at configure time.
	set(_all_manifest "${CMAKE_CURRENT_BINARY_DIR}/logray-manifest.nsh")
	set(_all_manifest_contents "# Files required for all sections. Generated by CMake.\n")
	set(_all_manifest_contents "${_all_manifest_contents}!ifdef BUNDLE_DEBUG_DLLS\n")
	foreach(_dll ${GLIB2_DLLS_DEBUG})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!else\n")
	foreach(_dll ${GLIB2_DLLS_RELEASE})
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	set(_all_manifest_contents "${_all_manifest_contents}!endif\n")
	foreach(_dll ${CARES_DLL} ${PCRE2_DLL} ${GCRYPT_DLLS}
			${GNUTLS_DLLS} ${KERBEROS_DLLS} ${LIBSSH_DLLS} ${LUA_DLL}
			${LZ4_DLL} ${NGHTTP2_DLL} ${SBC_DLL} ${SMI_DLL} ${SNAPPY_DLL}
			${SPANDSP_DLL} ${BCG729_DLL} ${LIBXML2_DLLS} ${WINSPARKLE_DLL}
			${ZLIB_DLL} ${BROTLI_DLLS} ${ZSTD_DLL} ${ILBC_DLL} ${OPUS_DLL}
			# Needed for mmdbresolve
			${MAXMINDDB_DLL}
		)
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_dll}\"\n")
	endforeach()
	foreach(_script "init.lua" "console.lua" "dtd_gen.lua")
		set(_all_manifest_contents "${_all_manifest_contents}File \"\${STAGING_DIR}\\${_script}\"\n")
	endforeach()
	file(WRITE "${_all_manifest}" "${_all_manifest_contents}")
endif()

file(TO_NATIVE_PATH "${DATAFILE_DIR}" _staging_dir)
file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}" _outfile_dir)
file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}" _nsis_include_dir)

# Variables we can't set via config.nsh.
set(NSIS_OPTIONS
	/DSTAGING_DIR=${_staging_dir}
	/DOUTFILE_DIR=${_outfile_dir}
	/DNSIS_INCLUDE_DIR=${_nsis_include_dir}
	/V2
	PARENT_SCOPE
)

# We want to sign all of the executables that we ship in the official
# installers. This means that uninstall-wireshark.exe must be built
# separately AND that building the installer itself won't overwrite
# uninstall-wireshark.exe
macro( ADD_NSIS_UNINSTALLER_TARGETS )
	set (_nsis_source_dir ${CMAKE_SOURCE_DIR}/packaging/nsis )
	set (_nsis_binary_dir ${CMAKE_BINARY_DIR}/packaging/nsis )

	#
	# XXX - if we're not building Wireshark, we can't build
	# anything, so there's nothing to uninstall.
	#
	if(BUILD_wireshark)
		add_custom_command(OUTPUT ${DATAFILE_DIR}/uninstall-wireshark.exe
			DEPENDS ${_nsis_source_dir}/uninstall-wireshark.nsi
				${_nsis_source_dir}/wireshark-common.nsh
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				uninstall-wireshark.nsi
			COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/makeUninstall.ps1" ${DATAFILE_DIR}/uninstall_wireshark_installer.exe
			COMMAND ${CMAKE_COMMAND} -E remove ${DATAFILE_DIR}/uninstall_wireshark_installer.exe
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
	else()
		message(WARNING "The NSIS installer cannot be built if the Wireshark program isn't built.")
	endif()

	if(BUILD_logray)
		add_custom_command(OUTPUT ${DATAFILE_DIR}/uninstall-logray.exe
			DEPENDS ${_nsis_source_dir}/uninstall-logray.nsi
				${_nsis_source_dir}/logray-common.nsh
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				uninstall-logray.nsi
			COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/makeUninstall.ps1" ${DATAFILE_DIR}/uninstall_logray_installer.exe
			COMMAND ${CMAKE_COMMAND} -E remove ${DATAFILE_DIR}/uninstall_logray_installer.exe
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
	endif()
endmacro( ADD_NSIS_UNINSTALLER_TARGETS )

macro( ADD_NSIS_PACKAGE_TARGETS )
	#
	# XXX - if we're not building Wireshark, we can't build the
	# manifest below.  On the other hand, if we're not building
	# Wireshark, we have no need to include Qt in the installer,
	# so it's not clear we need this manifest.
	#
	# This should probably be fixed, so that people can produce
	# command-line-only installer packages.
	if(BUILD_wireshark)
		#set (_nsis_package ${CMAKE_BINARY_DIR}/packaging/nsis/Wireshark-$(WIRESHARK_TARGET_PLATFORM)-$(VERSION).exe)

		# wireshark-qt-manifest.nsh. Created using Wireshark.exe.
		add_custom_command(OUTPUT ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
				-Executable $<TARGET_FILE:wireshark>
				-FilePath ${_nsis_binary_dir}/wireshark-qt-manifest.nsh
				$<$<CONFIG:Debug>:-DebugConfig>
			DEPENDS "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
		)

		# Build NSIS package dependencies. We build the package in
		# two stages so that wireshark_nsis below doesn't trigger
		# any dependencies that might clobber any signed executables.
		add_custom_target(wireshark_nsis_prep
			DEPENDS
				${WIRESHARK_NSIS_FILES}
				copy_data_files
				user_guide_html
				faq_html
				${DATAFILE_DIR}/uninstall-wireshark.exe
		)
		set_target_properties(wireshark_nsis_prep PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)

		# Dump the installer into
		# ${CMAKE_CURRENT_SOURCE_DIR}/packaging/nsis
		# Note that executables and DLLs *must* be built separately
		add_custom_target(wireshark_nsis
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				$<$<CONFIG:Debug>:/DBUNDLE_DEBUG_DLLS>
				wireshark.nsi
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
		set_target_properties(wireshark_nsis PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)
	endif()

	if(BUILD_logray)
		#set (_nsis_package ${CMAKE_BINARY_DIR}/packaging/nsis/Wireshark-$(WIRESHARK_TARGET_PLATFORM)-$(VERSION).exe)

		# logray-qt-manifest.nsh. Created using Wireshark.exe.
		add_custom_command(OUTPUT ${_nsis_binary_dir}/logray-qt-manifest.nsh
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND ${POWERSHELL_COMMAND} "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
				-Executable $<TARGET_FILE:logray>
				-FilePath ${_nsis_binary_dir}/logray-qt-manifest.nsh
				$<$<CONFIG:Debug>:-DebugConfig>
			DEPENDS "${_nsis_source_dir}/windeployqt-to-nsis.ps1"
		)

		# Build NSIS package dependencies. We build the package in
		# two stages so that logray_nsis below doesn't trigger
		# any dependencies that might clobber any signed executables.
		add_custom_target(logray_nsis_prep
			DEPENDS
				${LOGRAY_NSIS_FILES}
				copy_data_files
				user_guide_html
				faq_html
				${DATAFILE_DIR}/uninstall-logray.exe
		)
		set_target_properties(logray_nsis_prep PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)

		# Dump the installer into
		# ${CMAKE_CURRENT_SOURCE_DIR}/packaging/nsis
		# Note that executables and DLLs *must* be built separately
		add_custom_target(logray_nsis
			COMMAND ${MAKENSIS_EXECUTABLE} ${NSIS_OPTIONS}
				$<$<CONFIG:Debug>:/DBUNDLE_DEBUG_DLLS>
				logray.nsi
			WORKING_DIRECTORY ${_nsis_source_dir}
		)
		set_target_properties(logray_nsis PROPERTIES
			FOLDER "Packaging"
			EXCLUDE_FROM_DEFAULT_BUILD True
		)
	endif()
endmacro( ADD_NSIS_PACKAGE_TARGETS )

set(CLEAN_FILES
	#NEWS.txt
	#user-guide.chm
	${DATAFILE_DIR}/uninstall-wireshark.exe
	wireshark-$(WIRESHARK_TARGET_PLATFORM)-$(VERSION).exe
	wireshark-config.nsh
	wireshark-manifest.nsh
	wireshark-qt-manifest.nsh
	${DATAFILE_DIR}/uninstall-logray.exe
	logray-$(WIRESHARK_TARGET_PLATFORM)-$(VERSION).exe
	logray-config.nsh
	logray-manifest.nsh
	logray-qt-manifest.nsh
)
