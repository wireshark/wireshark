#
# - Find math
# Find the native M includes and library
#
#  M_INCLUDE_DIRS - where to find math.h, etc.
#  M_LIBRARIES    - List of libraries when using math.
#  M_FOUND        - True if math found.


IF (M_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(M_FIND_QUIETLY TRUE)
ENDIF (M_INCLUDE_DIRS)

FIND_PATH(M_INCLUDE_DIR math.h)

SET(M_NAMES m)
FIND_LIBRARY(M_LIBRARY NAMES ${M_NAMES} )

# handle the QUIETLY and REQUIRED arguments and set M_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(M DEFAULT_MSG M_LIBRARY M_INCLUDE_DIR)

IF(M_FOUND)
  SET( M_LIBRARIES ${M_LIBRARY} )
  SET( M_INCLUDE_DIRS ${M_INCLUDE_DIR} )
ELSE(M_FOUND)
  SET( M_LIBRARIES )
  SET( M_INCLUDE_DIRS )
ENDIF(M_FOUND)

MARK_AS_ADVANCED( M_LIBRARIES M_INCLUDE_DIRS )
