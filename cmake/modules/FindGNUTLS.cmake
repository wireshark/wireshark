#
# - Find gnutls
# Find the native GNUTLS includes and library
#
#  GNUTLS_INCLUDE_DIRS - where to find gnutls.h, etc.
#  GNUTLS_LIBRARIES    - List of libraries when using gnutls.
#  GNUTLS_FOUND        - True if gnutls found.


IF (GNUTLS_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(GNUTLS_FIND_QUIETLY TRUE)
ENDIF (GNUTLS_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("gnutls-.*" "GNUTLS_HINTS")

FIND_PATH(GNUTLS_INCLUDE_DIR
	NAMES
	  gnutls.h
	  gnutls/gnutls.h
	PATH_SUFFIXES
	  include
	HINTS
	  ${GNUTLS_HINTS}
)

SET(GNUTLS_NAMES gnutls libgnutls-28)
FIND_LIBRARY(GNUTLS_LIBRARY NAMES ${GNUTLS_NAMES} libgmp-10 libgcc_s_sjlj-1 libffi-6 libhogweed-2-4 libnettle-4-6 libp11-kit-0 libtasn1-6 HINTS "${GNUTLS_HINTS}/bin" )

# handle the QUIETLY and REQUIRED arguments and set GNUTLS_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GNUTLS DEFAULT_MSG GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR)

IF(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES ${GNUTLS_LIBRARY} )
  SET( GNUTLS_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIR} )
ELSE(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES )
  SET( GNUTLS_INCLUDE_DIRS )
ENDIF(GNUTLS_FOUND)

MARK_AS_ADVANCED( GNUTLS_LIBRARIES GNUTLS_INCLUDE_DIRS )
