#
# $Id$
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

INCLUDE( FindPkgConfig )

IF( GMODULE2_FIND_REQUIRED )
	SET( _pkgconfig_REQUIRED "REQUIRED" )
ELSE()
	SET( _pkgconfig_REQUIRED "" )
ENDIF()

IF( GMODULE2_MIN_VERSION )
	PKG_SEARCH_MODULE( GMODULE2 ${_pkgconfig_REQUIRED} gmodule-2.0>=${GMODULE2_MIN_VERSION} )
ELSE()
	PKG_SEARCH_MODULE( GMODULE2 ${_pkgconfig_REQUIRED} gmodule-2.0 )
ENDIF()

IF( NOT GMODULE2_FOUND  )
	INCLUDE( FindWSWinLibs )
	FindWSWinLibs( "gtk[23]" "GMODULE2_HINTS" )
	FIND_PATH( GMODULE2_INCLUDE_DIRS
		NAMES
			gmodule.h
		PATH_SUFFIXES
			glib-2.0
		HINTS
			"${GMODULE2_HINTS}/include"
	)
	IF( APPLE )
		FIND_LIBRARY( GMODULE2_LIBRARIES glib )
	ELSE()
		FIND_LIBRARY( GMODULE2_LIBRARIES NAMES gmodule-2.0 gmodule HINTS "${GMODULE2_HINTS}/lib" )
	ENDIF()
	INCLUDE( FindPackageHandleStandardArgs )
	FIND_PACKAGE_HANDLE_STANDARD_ARGS( GMODULE2 DEFAULT_MSG GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )
ENDIF()

MARK_AS_ADVANCED( GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS )
