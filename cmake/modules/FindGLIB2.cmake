#
# - Try to find the GLIB2 libraries
# Once done this will define
#
#  GLIB2_FOUND - system has glib2
#  GLIB2_INCLUDE_DIRS - the glib2 include directory
#  GLIB2_LIBRARIES - glib2 library

# Copyright (c) 2008 Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


if( GLIB2_MAIN_INCLUDE_DIR AND GLIB2_LIBRARIES )
	# Already in cache, be silent
	set( GLIB2_FIND_QUIETLY TRUE )
endif()

include( FindWSWinLibs )
if( BUILD_wireshark )
	if( ENABLE_GTK3 )
		FindWSWinLibs( "gtk3" "GLIB2_HINTS" )
	else()
		FindWSWinLibs( "gtk2" "GLIB2_HINTS" )
	endif()
else()
	message( ERROR "Unsupported build setup" )
endif()

find_package( PkgConfig )

if( GLIB2_MIN_VERSION )
	pkg_search_module( GLIB2 glib-2.0>=${GLIB2_MIN_VERSION} )
else()
	pkg_search_module( GLIB2 glib-2.0 )
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

find_library( GLIB2_LIBRARY
	NAMES
		glib-2.0
		libglib-2.0
	HINTS
		"${PC_GLIB2_LIBDIR}"
		"${GLIB2_HINTS}/lib"
	PATHS
		/opt/gnome/lib64
		/opt/gnome/lib
		/opt/lib/
		/opt/local/lib
		/sw/lib/
		/usr/lib64
		/usr/lib
)

# search the glibconfig.h include dir under the same root where the library is found
get_filename_component( glib2LibDir "${GLIB2_LIBRARY}" PATH)

find_path( GLIB2_INTERNAL_INCLUDE_DIR
	NAMES
		glibconfig.h
	HINTS
		"${PC_GLIB2_INCLUDEDIR}"
		"${glib2LibDir}"
		${CMAKE_SYSTEM_LIBRARY_PATH}
	PATH_SUFFIXES
		glib-2.0/include
	PATHS
		${GLIB2_LIBRARY}

)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( GLIB2
	DEFAULT_MSG
	GLIB2_LIBRARY
	GLIB2_MAIN_INCLUDE_DIR
)

if( GLIB2_FOUND )
	set( GLIB2_LIBRARIES ${GLIB2_LIBRARY} )
	set( GLIB2_INCLUDE_DIRS ${GLIB2_MAIN_INCLUDE_DIR} ${GLIB2_INTERNAL_INCLUDE_DIR} )
elseif( GLIB2_FIND_REQUIRED )
	message( SEND_ERROR "Package required but not found" )
else()
	set( GLIB2_LIBRARIES )
	set( GLIB2_MAIN_INCLUDE_DIRS )
endif()

mark_as_advanced( GLIB2_INCLUDE_DIRS GLIB2_LIBRARIES )

