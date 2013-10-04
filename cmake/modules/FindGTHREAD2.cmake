# - Try to find GThread2
#
# $Id$
#
# Find GThread headers, libraries and the answer to all questions.
#
#  GTHREAD2_FOUND               True if GTHREAD2 got found
#  GTHREAD2_INCLUDE_DIRS        Location of GTHREAD2 headers
#  GTHREAD2_LIBRARIES           List of libraries to use GTHREAD2
#
#  Copyright (c) 2008 Bjoern Ricks <bjoern.ricks@googlemail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

INCLUDE( FindPkgConfig )

IF( GTHREAD2_FIND_REQUIRED )
	SET( _pkgconfig_REQUIRED "REQUIRED" )
ELSE()
	SET( _pkgconfig_REQUIRED "" )
ENDIF()

IF( GTHREAD2_MIN_VERSION )
	PKG_SEARCH_MODULE( GTHREAD2 ${_pkgconfig_REQUIRED} gthread-2.0>=${GTHREAD2_MIN_VERSION} )
ELSE()
	PKG_SEARCH_MODULE( GTHREAD2 ${_pkgconfig_REQUIRED} gthread-2.0 )
ENDIF()


IF( NOT GTHREAD2_FOUND AND NOT PKG_CONFIG_FOUND )

	INCLUDE(FindWSWinLibs)
	FindWSWinLibs("gtk2" "GTHREAD2_HINTS")

	FIND_PATH( GTHREAD2_INCLUDE_DIRS gthread.h PATH_SUFFIXES glib-2.0 glib GLib.framework/Headers/glib glib-2.0/glib HINTS "${GTHREAD2_HINTS}/include" )
	IF( APPLE )
		FIND_LIBRARY( GTHREAD2_LIBRARIES glib )
	ELSE()
		FIND_LIBRARY( GTHREAD2_LIBRARIES gthread-2.0 HINTS "${GTHREAD2_HINTS}/lib" )
	ENDIF()

	INCLUDE(FindPackageHandleStandardArgs)
	FIND_PACKAGE_HANDLE_STANDARD_ARGS(GTHREAD2 DEFAULT_MSG GTHREAD2_LIBRARIES GTHREAD2_INCLUDE_DIRS)

	# Report results
	IF( GTHREAD2_FOUND )
		IF( NOT GTHREAD2_FIND_QUIETLY )
			MESSAGE( STATUS "Found GTHREAD2: ${GTHREAD2_LIBRARIES} ${GTHREAD2_INCLUDE_DIRS}" )
		ENDIF()
	ELSE()
		IF( GTHREAD2_FIND_REQUIRED )
			MESSAGE( SEND_ERROR "Could NOT find GTHREAD2" )
		ELSE()
			IF( NOT GTHREAD2_FIND_QUIETLY )
				MESSAGE( STATUS "Could NOT find GTHREAD2" )
			ENDIF()
		ENDIF()
	ENDIF()
ENDIF()

MARK_AS_ADVANCED( GTHREAD2_LIBRARIES GTHREAD2_INCLUDE_DIRS )
