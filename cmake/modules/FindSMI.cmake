#
# - Find smi
# Find the native SMI includes and library
#
#  SMI_INCLUDE_DIRS - where to find smi.h, etc.
#  SMI_LIBRARIES    - List of libraries when using smi.
#  SMI_FOUND        - True if smi found.


IF (SMI_INCLUDE_DIR)
  # Already in cache, be silent
  SET(SMI_FIND_QUIETLY TRUE)
ENDIF (SMI_INCLUDE_DIR)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("libsmi-.*" "SMI_HINTS")

FIND_PATH(SMI_INCLUDE_DIR smi.h HINTS "${SMI_HINTS}/include" )

SET(SMI_NAMES smi libsmi-2)
FIND_LIBRARY(SMI_LIBRARY NAMES ${SMI_NAMES} HINTS "${SMI_HINTS}/lib" )

# handle the QUIETLY and REQUIRED arguments and set SMI_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SMI DEFAULT_MSG SMI_LIBRARY SMI_INCLUDE_DIR)

IF(SMI_FOUND)
  SET( SMI_LIBRARIES ${SMI_LIBRARY} )
  SET( SMI_INCLUDE_DIRS ${SMI_INCLUDE_DIR} )
ELSE(SMI_FOUND)
  SET( SMI_LIBRARIES )
  SET( SMI_INCLUDE_DIRS )
ENDIF(SMI_FOUND)

MARK_AS_ADVANCED( SMI_LIBRARIES SMI_INCLUDE_DIRS )
