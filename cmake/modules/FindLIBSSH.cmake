# - Try to find LibSSH
# Once done this will define
#
#  LIBSSH_FOUND - system has LibSSH
#  LIBSSH_INCLUDE_DIRS - the LibSSH include directory
#  LIBSSH_LIBRARIES - Link these to use LibSSH
#
#  Copyright (c) 2009 Andreas Schneider <mail@cynapses.org>
#  Modified by Peter Wu <peter@lekensteyn.nl> to use standard
#  find_package(LIBSSH ...) without external module.
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

if(LIBSSH_LIBRARIES AND LIBSSH_INCLUDE_DIRS)
  # in cache already
  set(LIBSSH_FOUND TRUE)
else ()

  include(FindWSWinLibs)
  FindWSWinLibs("libssh-.*" "LIBSSH_HINTS")

  find_path(LIBSSH_INCLUDE_DIR
    NAMES
      libssh/libssh.h
    HINTS
      "${LIBSSH_HINTS}/include"
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBSSH_LIBRARY
    NAMES
      ssh
      libssh
    HINTS
      "${LIBSSH_HINTS}/lib"
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if(LIBSSH_INCLUDE_DIR AND LIBSSH_LIBRARY)
    set(LIBSSH_INCLUDE_DIRS
      ${LIBSSH_INCLUDE_DIR}
    )
    set(LIBSSH_LIBRARIES
      ${LIBSSH_LIBRARY}
    )

    file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MAJOR
      REGEX "#define[ ]+LIBSSH_VERSION_MAJOR[ ]+[0-9]+")
    # Older versions of libssh like libssh-0.2 have LIBSSH_VERSION but not LIBSSH_VERSION_MAJOR
    if(LIBSSH_VERSION_MAJOR)
      string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MAJOR ${LIBSSH_VERSION_MAJOR})
      file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_MINOR
        REGEX "#define[ ]+LIBSSH_VERSION_MINOR[ ]+[0-9]+")
      string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_MINOR ${LIBSSH_VERSION_MINOR})
      file(STRINGS ${LIBSSH_INCLUDE_DIR}/libssh/libssh.h LIBSSH_VERSION_PATCH
        REGEX "#define[ ]+LIBSSH_VERSION_MICRO[ ]+[0-9]+")
      string(REGEX MATCH "[0-9]+" LIBSSH_VERSION_PATCH ${LIBSSH_VERSION_PATCH})
      set(LIBSSH_VERSION ${LIBSSH_VERSION_MAJOR}.${LIBSSH_VERSION_MINOR}.${LIBSSH_VERSION_PATCH})
    endif()
  endif()

  # handle the QUIETLY and REQUIRED arguments and set LIBSSH_FOUND to TRUE if
  # all listed variables are TRUE and the requested version matches.
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LIBSSH
    REQUIRED_VARS   LIBSSH_LIBRARIES LIBSSH_INCLUDE_DIRS LIBSSH_VERSION
    VERSION_VAR     LIBSSH_VERSION)

  if(WIN32)
    set(LIBSSH_DLL_DIR "${LIBSSH_HINTS}/bin"
      CACHE PATH "Path to libssh DLL"
    )
    file(GLOB _libssh_dll RELATIVE "${LIBSSH_DLL_DIR}"
      "${LIBSSH_DLL_DIR}/libssh.dll"
    )
    set(LIBSSH_DLL ${_libssh_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "libssh DLL file name"
    )
    mark_as_advanced(LIBSSH_DLL_DIR LIBSSH_DLL)
  endif()

  # show the LIBSSH_INCLUDE_DIRS and LIBSSH_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBSSH_INCLUDE_DIRS LIBSSH_LIBRARIES)

endif()
