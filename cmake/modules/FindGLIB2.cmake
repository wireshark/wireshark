# - Try to find GLIB2
# Once done this will define
#
#  GLIB2_FOUND - system has GLIB2
#  GLIB2_INCLUDE_DIRS - the GLIB2 include directory
#  GLIB2_LIBRARIES - Link these to use GLIB2
#  GLIB2_DEFINITIONS - Compiler switches required for using GLIB2
#
#  Copyright (c) 2006 Andreas Schneider <mail@cynapses.org>
#  Copyright (c) 2006 Philippe Bernery <philippe.bernery@gmail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIRS)
  # in cache already
  set(GLIB2_FOUND TRUE)
else (GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIRS)
  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  include(UsePkgConfig)

  ## GLibConfig
  find_path(GLIBCONFIG_INCLUDE_DIR
    NAMES
      glibconfig.h
    PATHS
      ${_GLIB2IncDir}
      /opt/gnome/lib64/glib-2.0/include
      /opt/gnome/lib/glib-2.0/include
      /opt/lib/glib-2.0/include
      /usr/lib64/glib-2.0/include
      /usr/lib/glib-2.0/include
      /sw/lib/glib-2.0/include
  )
  ##

  ## Glib
  pkgconfig(glib-2.0 _GLIB2IncDir _GLIB2LinkDir _GLIB2LinkFlags _GLIB2Cflags)

  set(GLIB2_DEFINITIONS ${_GLIB2Cflags})

  find_path(GLIB2_INCLUDE_DIR
    NAMES
      glib.h
    PATHS
      ${_GLIB2IncDir}
      /opt/gnome/include/glib-2.0
      /usr/include/glib-2.0
      /usr/local/include/glib-2.0
      /opt/local/include/glib-2.0
      /sw/include/glib-2.0
  )

  find_library(GLIB2_LIBRARY
    NAMES
      glib-2.0
    PATHS
      ${_GLIB2LinkDir}
      /opt/gnome/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(GLIB2_LIBRARIES ${GLIB2_LIBRARY})
  set(GLIB2_INCLUDE_DIRS ${GLIB2_INCLUDE_DIR})
  ##

  ## GModule
  pkgconfig(gmodule-2.0 _GMODULE2IncDir _GMODULE2LinkDir _GMODULE2LinkFlags _GMODULE2Cflags)

  set(GMODULE2_DEFINITIONS ${_GMODULE2Cflags})

  find_path(GMODULE2_INCLUDE_DIR
    NAMES
      gmodule.h
    PATHS
      ${_GMODULE2IncDir}
      /opt/gnome/include/glib-2.0
      /usr/include/glib-2.0
      /usr/local/include/glib-2.0
      /opt/local/include/glib-2.0
      /sw/include/glib-2.0
  )
 
  find_library(GMODULE2_LIBRARY
    NAMES
      gmodule-2.0
    PATHS
      ${_GMODULE2LinkDir}
      /opt/gnome/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )
  if (GMODULE2_LIBRARY AND GMODULE2_INCLUDE_DIR)
    set(GMODULE2_FOUND TRUE)
  endif (GMODULE2_LIBRARY AND GMODULE2_INCLUDE_DIR)
  ##

  ## GThread
  pkgconfig(gthread-2.0 _GTHREAD2IncDir _GTHREAD2LinkDir _GTHREAD2LinkFlags _GTHREAD2Cflags)

  set(GTHREAD2_DEFINITIONS ${_GTHREAD2Cflags})

  find_path(GTHREAD2_INCLUDE_DIR
    NAMES
      gthread.h
    PATHS
      ${_GTHREAD2IncDir}
      /opt/gnome/include/glib-2.0
      /usr/include/glib-2.0
      /usr/local/include/glib-2.0
      /opt/local/include/glib-2.0
      /sw/include/glib-2.0
    PATH_SUFFIXES
      glib
  )
 
  find_library(GTHREAD2_LIBRARY
    NAMES
      gthread-2.0
    PATHS
      ${_GTHREAD2LinkDir}
      /opt/gnome/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  if (GTHREAD2_LIBRARY AND GTHREAD2_INCLUDE_DIR)
    set(GTHREAD2_FOUND TRUE)
  endif (GTHREAD2_LIBRARY AND GTHREAD2_INCLUDE_DIR)
  ##

  ## libintl
  find_path(LIBINTL_INCLUDE_DIR
    NAMES
      libintl.h
    PATHS
      /opt/gnome/include/glib-2.0
      /usr/include/glib-2.0
      /usr/local/include/glib-2.0
      /opt/local/include/glib-2.0
      /sw/include/glib-2.0
  )
 
  find_library(LIBINTL_LIBRARY
    NAMES
      intl
    PATHS
      /opt/gnome/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  if (LIBINTL_LIBRARY AND LIBINTL_INCLUDE_DIR)
    set(LIBINTL_FOUND TRUE)
  endif (LIBINTL_LIBRARY AND LIBINTL_INCLUDE_DIR)
  ##

  ## libiconv
  find_path(LIBICONV_INCLUDE_DIR
    NAMES
      iconv.h
    PATHS
      /opt/gnome/include/glib-2.0
      /usr/include/glib-2.0
      /usr/local/include/glib-2.0
      /opt/local/include/glib-2.0
      /sw/include/glib-2.0
  )
 
  find_library(LIBICONV_LIBRARY
    NAMES
      iconv
    PATHS
      /opt/gnome/lib
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  if (LIBICONV_LIBRARY AND LIBICONV_INCLUDE_DIR)
    set(LIBICONV_FOUND TRUE)
  endif (LIBICONV_LIBRARY AND LIBICONV_INCLUDE_DIR)
  ##

  set(GLIB2_INCLUDE_DIRS
    ${GLIB_INCLUDE_DIR}
    ${GLIBCONFIG_INCLUDE_DIR}
  )
  set(GLIB2_LIBRARIES
    ${GLIB_LIBRARY}
  )

  if (GMODULE2_FOUND)
    set(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${GMODULE2_LIBRARY})
    set(GLIB2_INCLUDE_DIRS ${GLIB2_INCLUDE_DIRS} ${GMODULE2_INCLUDE_DIR})
  endif (GMODULE2_FOUND)

  if (GTHREAD2_FOUND)
    set(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${GTHREAD2_LIBRARY})
    set(GLIB2_INCLUDE_DIRS ${GLIB2_INCLUDE_DIRS} ${GTHREAD2_INCLUDE_DIR})
  endif (GTHREAD2_FOUND)

  if (LIBINTL_FOUND)
    set(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${LIBINTL_LIBRARY})
    set(GLIB2_INCLUDE_DIRS ${GLIB2_INCLUDE_DIRS} ${LIBINTL_INCLUDE_DIR})
  endif (LIBINTL_FOUND)

  if (LIBICONV_FOUND)
    set(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${LIBICONV_LIBRARY})
    set(GLIB2_INCLUDE_DIRS ${GLIB2_INCLUDE_DIRS} ${LIBICONV_INCLUDE_DIR})
  endif (LIBICONV_FOUND)

  if (GLIB2_INCLUDE_DIRS AND GLIB2_LIBRARIES)
     set(GLIB2_FOUND TRUE)
  endif (GLIB2_INCLUDE_DIRS AND GLIB2_LIBRARIES)

  if (GLIB2_FOUND)
    if (NOT GLIB2_FIND_QUIETLY)
      message(STATUS "Found GLIB2: ${GLIB2_LIBRARIES}")
    endif (NOT GLIB2_FIND_QUIETLY)
  else (GLIB2_FOUND)
    if (GLIB2_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find GLIB2")
    endif (GLIB2_FIND_REQUIRED)
  endif (GLIB2_FOUND)

  # show the GLIB2_INCLUDE_DIRS and GLIB2_LIBRARIES variables only in the advanced view
  mark_as_advanced(GLIB2_INCLUDE_DIRS GLIB2_LIBRARIES)

endif (GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIRS)
