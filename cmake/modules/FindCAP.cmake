#
# $Id$
#
# - Find capabilities
# Find the native CAP includes and library
#
#  CAP_INCLUDE_DIRS - where to find cap.h, etc.
#  CAP_LIBRARIES    - List of libraries when using cap.
#  CAP_FOUND        - True if cap found.


IF (CAP_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(CAP_FIND_QUIETLY TRUE)
ENDIF (CAP_INCLUDE_DIRS)

FIND_PATH(CAP_INCLUDE_DIR sys/capability.h)

SET(CAP_NAMES cap)
FIND_LIBRARY(CAP_LIBRARY NAMES ${CAP_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set CAP_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CAP DEFAULT_MSG CAP_LIBRARY CAP_INCLUDE_DIR)

IF(CAP_FOUND)
  SET( CAP_LIBRARIES ${CAP_LIBRARY} )
  SET( CAP_INCLUDE_DIRS ${CAP_INCLUDE_DIR} )
ELSE(CAP_FOUND)
  SET( CAP_LIBRARIES )
  SET( CAP_INCLUDE_DIRS )
ENDIF(CAP_FOUND)

MARK_AS_ADVANCED( CAP_LIBRARIES CAP_INCLUDE_DIRS )
