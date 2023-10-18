#
# - Try to find the GLIB2 libraries
# Once done this will define
#
#  GLIB2_FOUND           - system has glib2
#  GLIB2_INCLUDE_DIRS    - the glib2 include directory
#  GLIB2_LIBRARIES       - glib2 library
#  GLIB2_DLL_DIR_DEBUG   - (Windows) Path to required GLib2 DLLs in debug build.
#  GLIB2_DLL_DIR_RELEASE - (Windows) Path to required GLib2 DLLs in release builds.
#  GLIB2_DLLS_DEBUG      - (Windows) List of required GLib2 DLLs in debug builds.
#  GLIB2_DLLS_RELEASE    - (Windows) List of required GLib2 DLLs in release builds.

# Copyright (c) 2008 Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


if( GLIB2_MAIN_INCLUDE_DIR AND GLIB2_LIBRARIES )
	# Already in cache, be silent
	set( GLIB2_FIND_QUIETLY TRUE )
endif()

include( FindWSWinLibs )
FindWSWinLibs( "vcpkg-export-*" "GLIB2_HINTS" )

if (NOT USE_REPOSITORY)
	find_package(PkgConfig)
	pkg_search_module( PC_GLIB2 glib-2.0 )
endif()

find_path( GLIB2_MAIN_INCLUDE_DIR
	NAMES
		glib.h
	HINTS
		"${PC_GLIB2_INCLUDEDIR}"
		"${GLIB2_HINTS}/include"
	PATH_SUFFIXES
		glib-2.0
		glib-2.0/include
	PATHS
		/opt/gnome/include
		/opt/local/include
		/sw/include
		/usr/include
		/usr/local/include
)

include(FindWSLibrary)
FindWSLibrary( GLIB2_LIBRARY
	NAMES
		glib-2.0
		libglib-2.0
	HINTS
		"${PC_GLIB2_LIBDIR}"
	WIN32_HINTS
	    ${GLIB2_HINTS}
	PATHS
		/opt/gnome/lib64
		/opt/gnome/lib
		/opt/lib/
		/opt/local/lib
		/sw/lib/
		/usr/lib64
		/usr/lib
)

if (USE_REPOSITORY)
	# In the Windows vcpkg port glibconfig.h is in
	# installed/$ARCH-windows/lib/glib-2.0/include.
	set( glib2LibDir "${GLIB2_HINTS}/lib" )
else()
	# On UNIX and UNIX-like platforms, the glibconfig.h include dir
	# should be in glib-2.0/include in the library directory.
	get_filename_component( glib2LibDir "${GLIB2_LIBRARY}" PATH)
endif()

find_path( GLIB2_INTERNAL_INCLUDE_DIR
	NAMES
		glibconfig.h
	HINTS
		"${PC_GLIB2_LIBDIR}"
		"${glib2LibDir}"
		"${GLIB2_INCLUDEDIR}"
		${CMAKE_SYSTEM_LIBRARY_PATH}
	PATH_SUFFIXES
		glib-2.0/include
)

if(PC_GLIB2_VERSION)
	set(GLIB2_VERSION ${PC_GLIB2_VERSION})
elseif(GLIB2_INTERNAL_INCLUDE_DIR)
	# On systems without pkg-config (e.g. Windows), search its header
	# (available since the initial commit of GLib).
	file(STRINGS ${GLIB2_INTERNAL_INCLUDE_DIR}/glibconfig.h GLIB_MAJOR_VERSION
		REGEX "#define[ ]+GLIB_MAJOR_VERSION[ ]+[0-9]+")
	string(REGEX MATCH "[0-9]+" GLIB_MAJOR_VERSION ${GLIB_MAJOR_VERSION})
	file(STRINGS ${GLIB2_INTERNAL_INCLUDE_DIR}/glibconfig.h GLIB_MINOR_VERSION
		REGEX "#define[ ]+GLIB_MINOR_VERSION[ ]+[0-9]+")
	string(REGEX MATCH "[0-9]+" GLIB_MINOR_VERSION ${GLIB_MINOR_VERSION})
	file(STRINGS ${GLIB2_INTERNAL_INCLUDE_DIR}/glibconfig.h GLIB_MICRO_VERSION
		REGEX "#define[ ]+GLIB_MICRO_VERSION[ ]+[0-9]+")
	string(REGEX MATCH "[0-9]+" GLIB_MICRO_VERSION ${GLIB_MICRO_VERSION})
	set(GLIB2_VERSION ${GLIB_MAJOR_VERSION}.${GLIB_MINOR_VERSION}.${GLIB_MICRO_VERSION})
else()
	# When using VERSION_VAR it must be set to a valid value or undefined to
	# mean "not found". It's not enough to use the empty string or any other CMake false boolean.
	unset(GLIB2_VERSION)
endif()

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( GLIB2
	REQUIRED_VARS   GLIB2_LIBRARY GLIB2_MAIN_INCLUDE_DIR GLIB2_INTERNAL_INCLUDE_DIR
	VERSION_VAR     GLIB2_VERSION
)

if( GLIB2_FOUND )
	set( GLIB2_LIBRARIES ${GLIB2_LIBRARY} )
	# Include transitive dependencies for static linking.
	if(UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a")
		find_library(PCRE_LIBRARY pcre)
		list(APPEND GLIB2_LIBRARIES -pthread ${PCRE_LIBRARY})
	endif()
	set( GLIB2_INCLUDE_DIRS ${GLIB2_MAIN_INCLUDE_DIR} ${GLIB2_INTERNAL_INCLUDE_DIR} )
	if ( USE_REPOSITORY AND GLIB2_FOUND )
		set ( GLIB2_DLL_DIR_RELEASE "${GLIB2_HINTS}/bin"
			CACHE PATH "Path to GLib2 release DLLs"
		)
		set ( GLIB2_DLL_DIR_DEBUG "${GLIB2_HINTS}/debug/bin"
			CACHE PATH "Path to GLib2 debug DLLs"
		)

		# GTK+ required GObject and GIO. We probably don't.
		file( GLOB _glib2_dlls_release RELATIVE "${GLIB2_DLL_DIR_RELEASE}"
			# "${GLIB2_DLL_DIR_RELEASE}/gio-2.0-0.dll"
			"${GLIB2_DLL_DIR_RELEASE}/glib-2.0-0.dll"
			"${GLIB2_DLL_DIR_RELEASE}/gmodule-2.0-0.dll"
			# "${GLIB2_DLL_DIR_RELEASE}/gobject-2.0-0.dll"
			"${GLIB2_DLL_DIR_RELEASE}/gthread-2.0-0.dll"
			"${GLIB2_DLL_DIR_RELEASE}/charset-1.dll"
			# gnutls-3.6.3-1-win64ws ships with libffi-6.dll
			# "${GLIB2_DLL_DIR_RELEASE}/libffi.dll"
			"${GLIB2_DLL_DIR_RELEASE}/iconv-2.dll"
			"${GLIB2_DLL_DIR_RELEASE}/intl-8.dll"
		)
		set ( GLIB2_DLLS_RELEASE ${_glib2_dlls_release}
			# We're storing filenames only. Should we use STRING instead?
			CACHE FILEPATH "GLib 2 release DLL list"
		)
		file( GLOB _glib2_dlls_debug RELATIVE "${GLIB2_DLL_DIR_DEBUG}"
			# "${GLIB2_DLL_DIR_DEBUG}/gio-2.0-0.dll"
			"${GLIB2_DLL_DIR_DEBUG}/glib-2.0-0.dll"
			"${GLIB2_DLL_DIR_DEBUG}/gmodule-2.0-0.dll"
			# "${GLIB2_DLL_DIR_DEBUG}/gobject-2.0-0.dll"
			"${GLIB2_DLL_DIR_DEBUG}/gthread-2.0-0.dll"
			"${GLIB2_DLL_DIR_DEBUG}/charset-1.dll"
			# gnutls-3.6.3-1-win64ws ships with libffi-6.dll
			# "${GLIB2_DLL_DIR_DEBUG}/libffi.dll"
			"${GLIB2_DLL_DIR_DEBUG}/iconv-2.dll"
			"${GLIB2_DLL_DIR_DEBUG}/intl-8.dll"
		)
		set ( GLIB2_DLLS_DEBUG ${_glib2_dlls_debug}
			# We're storing filenames only. Should we use STRING instead?
			CACHE FILEPATH "GLib 2 debug DLL list"
		)

		file( GLOB _glib2_pdbs_release RELATIVE "${GLIB2_DLL_DIR_RELEASE}"
			"${GLIB2_DLL_DIR_RELEASE}/glib-2.0-0.pdb"
			"${GLIB2_DLL_DIR_RELEASE}/gmodule-2.0-0.pdb"
			"${GLIB2_DLL_DIR_RELEASE}/gthread-2.0-0.pdb"
			# "${GLIB2_DLL_DIR_RELEASE}/libcharset.pdb"
			# "${GLIB2_DLL_DIR_RELEASE}/libiconv.pdb"
			# "${GLIB2_DLL_DIR_RELEASE}/libintl.pdb"
		)
		set ( GLIB2_PDBS_RELEASE ${_glib2_pdbs_release}
			CACHE FILEPATH "GLib2 debug release PDB list"
		)
		file( GLOB _glib2_pdbs_debug RELATIVE "${GLIB2_DLL_DIR_DEBUG}"
			"${GLIB2_DLL_DIR_DEBUG}/glib-2.0-0.pdb"
			"${GLIB2_DLL_DIR_DEBUG}/gmodule-2.0-0.pdb"
			"${GLIB2_DLL_DIR_DEBUG}/gthread-2.0-0.pdb"
			# "${GLIB2_DLL_DIR_DEBUG}/libcharset.pdb"
			# "${GLIB2_DLL_DIR_DEBUG}/libiconv.pdb"
			# "${GLIB2_DLL_DIR_DEBUG}/libintl.pdb"
		)
		set ( GLIB2_PDBS_DEBUG ${_glib2_pdbs_debug}
			CACHE FILEPATH "GLib2 debug debug PDB list"
		)

		mark_as_advanced( GLIB2_DLL_DIR_RELEASE GLIB2_DLLS_RELEASE GLIB2_PDBS_RELEASE )
		mark_as_advanced( GLIB2_DLL_DIR_DEBUG GLIB2_DLLS_DEBUG GLIB2_PDBS_DEBUG )
	endif()
elseif( GLIB2_FIND_REQUIRED )
	message( SEND_ERROR "Package required but not found" )
else()
	set( GLIB2_LIBRARIES )
	set( GLIB2_MAIN_INCLUDE_DIRS )
	set( GLIB2_DLL_DIR_RELEASE )
	set( GLIB2_DLL_DIR_DEBUG )
	set( GLIB2_PDBS_RELEASE )
	set( GLIB2_PDBS_DEBUG )
	set( GLIB2_DLLS )
endif()

mark_as_advanced( GLIB2_INCLUDE_DIRS GLIB2_LIBRARIES )
