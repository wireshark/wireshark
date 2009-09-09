# - Find zlib
# Find the native ZLIB includes and library
#
#  Z_INCLUDE_DIRS - where to find zlib.h, etc.
#  Z_LIBRARIES    - List of libraries when using zlib.
#  Z_FOUND        - True if zlib found.


IF (Z_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(Z_FIND_QUIETLY TRUE)
ENDIF (Z_INCLUDE_DIRS)

FIND_PATH(Z_INCLUDE_DIR zlib.h)

SET(Z_NAMES z zlib zdll)
FIND_LIBRARY(Z_LIBRARY NAMES ${Z_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set Z_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Z DEFAULT_MSG Z_LIBRARY Z_INCLUDE_DIR)

IF(Z_FOUND)
  SET( Z_LIBRARIES ${Z_LIBRARY} )
  SET( Z_INCLUDE_DIRS ${Z_INCLUDE_DIR} )
ELSE(Z_FOUND)
  SET( Z_LIBRARIES )
  SET( Z_INCLUDE_DIRS )
ENDIF(Z_FOUND)

MARK_AS_ADVANCED( Z_LIBRARIES Z_INCLUDE_DIRS )
