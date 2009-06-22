# - try to find GLIB and gmodule
#  GLIB_INCLUDE_DIR		- Directories to include to use GLIB
#  GLIB_LIBRARIES		- Files to link against to use GLIB
#  GLIB_FOUND			- GLIB was found
#  GLIB_gmodule_LIBRARIES
#  GLIB_gthread_LIBRARIES


# don't even bother under WIN32
IF(UNIX)

  # Some Linux distributions (e.g. Red Hat) have glibconfig.h
  # and glib.h in different directories, so we need to look
  # for both.
  #  - Atanas Georgiev <atanas@cs.columbia.edu>

  FIND_PATH( GLIB_glibconfig_INCLUDE_PATH glibconfig.h
    /usr/include
    /usr/local/include
    /usr/openwin/share/include
    /usr/local/include/glib12
    /usr/lib/glib/include
    /usr/local/lib/glib/include
    /opt/gnome/include
    /opt/gnome/lib/glib/include
  )

  FIND_PATH( GLIB_glib_INCLUDE_PATH glib.h
    /usr/include
    /usr/local/include
    /usr/openwin/share/include
    /usr/local/include/glib12
    /usr/lib/glib/include
    /usr/include/glib-1.2
    /usr/local/include/glib-1.2
    /opt/gnome/include
    /opt/gnome/include/glib-1.2
  )

  #
  # The 12 suffix is thanks to the FreeBSD ports collection
  #

  FIND_LIBRARY( GLIB_gtk_LIBRARIES
    NAMES  gtk gtk12
    PATHS /usr/lib
          /usr/local/lib
          /usr/openwin/lib
          /usr/X11R6/lib
          /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB_gmodule_LIBRARIES
    NAMES  gmodule gmodule12
    PATHS  /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB_glib_LIBRARIES
    NAMES  glib glib12
    PATHS  /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GLIB_gthread_LIBRARIES
    NAMES  gthread gthread12
    PATHS  /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  IF(GLIB_glibconfig_INCLUDE_PATH)
  IF(GLIB_glib_INCLUDE_PATH)
  IF(GLIB_glib_LIBRARIES)

    # Assume that if gtk and glib were found, the other
    # supporting libraries have also been found.

    SET( GLIB_FOUND "YES" )
    SET( GLIB_INCLUDE_DIR  ${GLIB_glibconfig_INCLUDE_PATH}
                           ${GLIB_glib_INCLUDE_PATH} )
    SET( GLIB_LIBRARIES    ${GLIB_glib_LIBRARIES} )

    IF(GLIB_gmodule_LIBRARIES)
      SET(GLIB_LIBRARIES ${GLIB_LIBRARIES} ${GLIB_gmodule_LIBRARIES})
    ENDIF(GLIB_gmodule_LIBRARIES)
    IF(GLIB_gthread_LIBRARIES)
      SET(GLIB_LIBRARIES ${GLIB_LIBRARIES} ${GLIB_gthread_LIBRARIES})
    ENDIF(GLIB_gthread_LIBRARIES)

  ENDIF(GLIB_glib_LIBRARIES)
  ENDIF(GLIB_glib_INCLUDE_PATH) 
  ENDIF(GLIB_glibconfig_INCLUDE_PATH)

  MARK_AS_ADVANCED(
    GLIB_glib_INCLUDE_PATH
    GLIB_glib_LIBRARIES
    GLIB_glibconfig_INCLUDE_PATH
    GLIB_gmodule_LIBRARIES
    GLIB_gthread_LIBRARIES
  )

ENDIF(UNIX)

