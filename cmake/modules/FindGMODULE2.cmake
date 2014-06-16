#
# - Try to find GModule2
# Find GModule headers, libraries and the answer to all questions.
#
#  GMODULE2_FOUND               True if GMODULE2 got found
#  GMODULE2_INCLUDE_DIRS        Location of GMODULE2 headers
#  GMODULE2_LIBRARIES           List of libraries to use GMODULE2
#
#  Copyright (c) 2008 Bjoern Ricks <bjoern.ricks@googlemail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

include( FindPkgConfig )

if( GMODULE2_FIND_REQUIRED )
	set( _pkgconfig_REQUIRED "REQUIRED" )
else()
	set( _pkgconfig_REQUIRED "" )
endif()

if( GMODULE2_MIN_VERSION )
	pkg_search_module( GMODULE2 ${_pkgconfig_REQUIRED} gmodule-2.0>=${GMODULE2_MIN_VERSION} )
else()
	pkg_search_module( GMODULE2 ${_pkgconfig_REQUIRED} gmodule-2.0 )
endif()

if( GMODULE2_FOUND  )
	if( GMODULE2_LIBRARY_DIRS )
		LINK_DIRECTORIES( ${GMODULE2_LIBRARY_DIRS} )
	endif()
else()
	include( FindWSWinLibs )
	if( BUILD_wireshark )
		if( ENABLE_GTK3 )
			FindWSWinLibs( "gtk3" "GMODULE2_HINTS" )
		else()
			FindWSWinLibs( "gtk2" "GMODULE2_HINTS" )
		endif()
	else()
		message( ERROR "Unsupported build setup" )
	endif()
	find_path( GMODULE2_INCLUDE_DIRS
		NAMES
			gmodule.h
		PATH_SUFFIXES
			glib-2.0
		HINTS
			"${GMODULE2_HINTS}/include"
	)
	find_library( GMODULE2_LIBRARIES NAMES gmodule-2.0 gmodule HINTS "${GMODULE2_HINTS}/lib" )
	if( NOT GMODULE2_LIBRARIES AND APPLE )
		# Fallback as APPLE glib libs already contain this - except
		# Homebrew which needs the non-Apple setup
		find_library( GMODULE2_LIBRARIES glib )
	endif()
	include( FindPackageHandleStandardArgs )
	find_package_handle_standard_args( GMODULE2 DEFAULT_MSG GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )
endif()

mark_as_advanced( GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )
