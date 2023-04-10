# Find the system's SpeexDSP includes and library
#
#  SPEEXDSP_INCLUDE_DIRS - where to find SpeexDSP headers
#  SPEEXDSP_LIBRARIES    - List of libraries when using SpeexDSP
#  SPEEXDSP_FOUND        - True if SpeexDSP found
#  SPEEXDSP_DLL_DIR      - (Windows) Path to the SpeexDSP DLL
#  SPEEXDSP_DLL          - (Windows) Name of the SpeexDSP DLL

include(FindWSWinLibs)
FindWSWinLibs("speexdsp-.*" "SPEEXDSP_HINTS")

if(NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(PC_SPEEXDSP speexdsp)
endif()


find_path(SPEEXDSP_INCLUDE_DIR
  NAMES
    speex/speex_resampler.h
  HINTS
    ${PC_SPEEXDSP_INCLUDE_DIRS}
    ${SPEEXDSP_HINTS}/include
)

find_library(SPEEXDSP_LIBRARY
  NAMES
    speexdsp
  HINTS
    ${PC_SPEEXDSP_LIBRARY_DIRS}
    ${SPEEXDSP_HINTS}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SpeexDSP DEFAULT_MSG SPEEXDSP_LIBRARY SPEEXDSP_INCLUDE_DIR)

if(SPEEXDSP_FOUND)
  set(SPEEXDSP_LIBRARIES ${SPEEXDSP_LIBRARY})
  set(SPEEXDSP_INCLUDE_DIRS ${SPEEXDSP_INCLUDE_DIR})
  if(WIN32)
    set(SPEEXDSP_DLL_DIR "${SPEEXDSP_HINTS}/bin"
      CACHE PATH "Path to SpeexDSP DLL"
    )
    file(GLOB _speexdsp_dll RELATIVE "${SPEEXDSP_DLL_DIR}"
      "${SPEEXDSP_DLL_DIR}/libspeexdsp.dll"
    )
    set(SPEEXDSP_DLL ${_speexdsp_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "SpeexDSP DLL file name"
    )
    mark_as_advanced(SPEEXDSP_DLL_DIR SPEEXDSP_DLL)
  endif()
else()
  set(SPEEXDSP_LIBRARIES)
  set(SPEEXDSP_INCLUDE_DIRS)
endif()

mark_as_advanced(SPEEXDSP_LIBRARIES SPEEXDSP_INCLUDE_DIRS)
