#
# try to find GLIB2 (and glib) and GLIBGLArea
#
#
# Jan Woetzel 06/2004: added /opt/gnome/include/gtk-1.2 path and $ENV{GLIB2_HOME}
# Andreas Schneider 08/2006: added pkgconfig, added lib64 include dirs
# Joerg Mayer 2006-08-31: rename GLIB to GLIB2


# GLIB2_INCLUDE_DIR   - Directories to include to use GLIB
# GLIB2_LIBRARIES     - Files to link against to use GLIB
# GLIB2_FOUND         - If false, don't try to use GLIB


# don't even bother under WIN32
IF(UNIX)
  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  INCLUDE(UsePkgConfig)

  # Some Linux distributions (e.g. Red Hat) have glibconfig.h
  # and glib.h in different directories, so we need to look
  # for both.
  #  - Atanas Georgiev <atanas@cs.columbia.edu>
  PKGCONFIG(glib-2.0 _GLIB2IncDir _GLIB2inkDir _GLIB2LinkFlags _GLIB2Cflags)
  PKGCONFIG(gmodule-2.0 _GMODULE2IncDir _GMODULE2inkDir _GMODULE2LinkFlags _GMODULE2Cflags)
  SET(GDIR /opt/gnome/lib/glib-2.0/include)

  FIND_PATH(GLIB2_glibconfig_INCLUDE_PATH glibconfig.h
    ${_GLIB2IncDir}
    /opt/gnome/lib64/glib-2.0/include
    /opt/gnome/lib/glib-2.0/include
    /usr/lib64/glib-2.0/include
    /usr/lib/glib-2.0/include
  )

  FIND_PATH(GLIB2_glib_INCLUDE_PATH glib.h
    ${_GLIB2IncDir}
    /opt/gnome/include/glib-2.0
    /usr/include/glib-2.0
  )

  FIND_LIBRARY( GLIB2_gmodule_LIBRARY
    NAMES  gmodule-2.0
    PATHS  ${_GMODULE2inkDir}
           /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB2_glib_LIBRARY
    NAMES  glib-2.0
    PATHS  ${_GLIB2inkDir}
           /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB2_gthread_LIBRARY
    NAMES  gthread-2.0
    PATHS  /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB2_gobject_LIBRARY
    NAMES  gobject-2.0
    PATHS 
           /opt/gnome/lib
  )

  IF(GLIB2_glibconfig_INCLUDE_PATH)
    IF(GLIB2_glib_INCLUDE_PATH)
      IF(GLIB2_glib_LIBRARY)
	
	SET( GLIB2_FOUND TRUE )
	SET( GLIB2_INCLUDE_DIR
          ${GLIB2_glibconfig_INCLUDE_PATH}
          ${GLIB2_glib_INCLUDE_PATH})
	SET( GLIB2_LIBRARIES ${GLIB2_glib_LIBRARY} )
    
        IF(GLIB2_gmodule_LIBRARY)
  	  SET(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${GLIB2_gmodule_LIBRARY})
        ENDIF(GLIB2_gmodule_LIBRARY)
        IF(GLIB2_gthread_LIBRARY)
          SET(GLIB2_LIBRARIES ${GLIB2_LIBRARIES} ${GLIB2_gthread_LIBRARY})
        ENDIF(GLIB2_gthread_LIBRARY)

      ELSE(GLIB2_glib_LIBRARY)
        MESSAGE("Can not find glib lib")
      ENDIF(GLIB2_glib_LIBRARY)
    ELSE(GLIB2_glib_INCLUDE_PATH) 
      MESSAGE("Can not find glib includes")
    ENDIF(GLIB2_glib_INCLUDE_PATH) 
  ELSE(GLIB2_glibconfig_INCLUDE_PATH)
    MESSAGE("Can not find glibconfig")
  ENDIF(GLIB2_glibconfig_INCLUDE_PATH)

  if (GLIB2_FOUND)
    if (NOT GLIB2_FIND_QUIETLY)
      message(STATUS "Found GLIB: ${GLIB2_LIBRARIES}")
    endif (NOT GLIB2_FIND_QUIETLY)
  else (GLIB2_FOUND)
    if (GLIB2_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find GLIB")
    endif (GLIB2_FIND_REQUIRED)
  endif (GLIB2_FOUND)


  MARK_AS_ADVANCED(
    GLIB2_glib_INCLUDE_PATH
    GLIB2_glib_LIBRARY
    GLIB2_glibconfig_INCLUDE_PATH
    GLIB2_gmodule_LIBRARY
    GLIB2_gthread_LIBRARY
  )

ELSE(UNIX)
  # MESSAGE("FindGLIB2 is working on UNIX/LINUX, only!")
ENDIF(UNIX)

