# - Find adns
# Find the gnu adns includes and library
# http://www.chiark.greenend.org.uk/~ian/adns/
#
#  ADNS_INCLUDE_DIRS - where to find adns.h, etc.
#  ADNS_LIBRARIES   - List of libraries when using adns.
#  ADNS_FOUND       - True if adns found.

#Includes
FIND_PATH(ADNS_INCLUDE_DIR adns.h
  /usr/local/include
  /usr/include
)

SET(ADNS_INCLUDE_DIRS ${ADNS_INCLUDE_DIR})

#Library
FIND_LIBRARY(ADNS_LIBRARY
  NAMES adns
  PATHS /usr/lib /usr/local/lib
)

SET(ADNS_LIBRARIES ${ADNS_LIBRARY})

#Is adns found ?
IF(ADNS_INCLUDE_DIR AND ADNS_LIBRARY)
  SET( ADNS_FOUND "YES" )
ENDIF(ADNS_INCLUDE_DIR AND ADNS_LIBRARY)


MARK_AS_ADVANCED(
  ADNS_LIBRARY
  ADNS_INCLUDE_DIR
)
