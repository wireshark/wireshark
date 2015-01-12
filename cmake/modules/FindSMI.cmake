#
# - Find smi
# Find the native SMI includes and library
#
#  SMI_INCLUDE_DIRS - where to find smi.h, etc.
#  SMI_LIBRARIES    - List of libraries when using smi.
#  SMI_FOUND        - True if smi found.
#  SMI_DLL_DIR      - (Windows) Path to the SMI DLL.
#  SMI_DLL          - (Windows) Name of the SMI DLL.
#  SMI_SHARE_DIR    - (Windows) Path to the SMI MIBs.


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
  if (WIN32)
    set ( SMI_DLL_DIR "${SMI_HINTS}/bin"
      CACHE PATH "Path to the SMI DLL"
    )
    set ( SMI_SHARE_DIR "${SMI_HINTS}/share"
      CACHE PATH "Path to the SMI MIBs"
    )
    file( GLOB _smi_dll RELATIVE "${SMI_DLL_DIR}"
      "${SMI_DLL_DIR}/libsmi-*.dll"
    )
    set ( SMI_DLL ${_smi_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "SMI DLL file name"
    )
    mark_as_advanced( SMI_DLL_DIR SMI_DLL )
  endif()
ELSE(SMI_FOUND)
  SET( SMI_LIBRARIES )
  SET( SMI_INCLUDE_DIRS )
  SET( SMI_DLL_DIR )
  SET( SMI_SHARE_DIR )
  SET( SMI_DLL )
ENDIF(SMI_FOUND)

MARK_AS_ADVANCED( SMI_LIBRARIES SMI_INCLUDE_DIRS )
