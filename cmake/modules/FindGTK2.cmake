#
# try to find GTK2 (and glib) and GTKGLArea
#
#
# Jan Woetzel 06/2004: added /opt/gnome/include/gtk-1.2 path and $ENV{GTK2_HOME}
# Andreas Schneider 08/2006: added pkgconfig, added lib64 include dirs
# Joerg Mayer 2006-08-31: rename GTK to GTK2


# GTK2_INCLUDE_DIR   - Directories to include to use GTK
# GTK2_LIBRARIES     - Files to link against to use GTK
# GTK2_FOUND         - If false, don't try to use GTK
# GTK2_GL_FOUND      - If false, don't try to use GTK's GL features


# don't even bother under WIN32
IF(UNIX)
  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  INCLUDE(UsePkgConfig)

  PKGCONFIG(gtk+-2.0 _GTK2IncDir _GTK2LinkDir _GTK2LinkFlags _GTK2Cflags)

  FIND_PATH(GTK2_gtk_INCLUDE_PATH gtk/gtk.h
    $ENV{GTK2_HOME}
    ${_GTK2IncDir}
    /usr/include/gtk-2.0
    /usr/local/include/gtk-2.0
    /opt/gnome/include/gtk-2.0  )

  # Some Linux distributions (e.g. Red Hat) have glibconfig.h
  # and glib.h in different directories, so we need to look
  # for both.
  #  - Atanas Georgiev <atanas@cs.columbia.edu>
  PKGCONFIG(glib-2.0 _GLIB2IncDir _GLIB2inkDir _GLIB2LinkFlags _GLIB2Cflags)
  PKGCONFIG(gmodule-2.0 _GMODULE2IncDir _GMODULE2inkDir _GMODULE2LinkFlags _GMODULE2Cflags)
  SET(GDIR /opt/gnome/lib/glib-2.0/include)
  FIND_PATH(GTK2_glibconfig_INCLUDE_PATH glibconfig.h
    ${_GLIB2IncDir}
    /opt/gnome/lib64/glib-2.0/include
    /opt/gnome/lib/glib-2.0/include
    /usr/lib64/glib-2.0/include
    /usr/lib/glib-2.0/include
  )
MESSAGE("GTK2_glibconfig_INCLUDE_PATH = ${GTK2_glibconfig_INCLUDE_PATH}")

  FIND_PATH(GTK2_glib_INCLUDE_PATH glib.h
    ${_GLIB2IncDir}
    /opt/gnome/include/glib-2.0
    /usr/include/glib-2.0
  )
# MESSAGE(" = ${}")

  FIND_PATH(GTK2_gtkgl_INCLUDE_PATH gtkgl/gtkglarea.h
    ${_GLIB2IncDir}
    /usr/include
    /usr/local/include
    /usr/openwin/share/include
    /opt/gnome/include
  )

  PKGCONFIG(pango _PANGOIncDir _PANGOinkDir _PANGOLinkFlags _PANGOCflags)

  FIND_PATH(GTK2_pango_INCLUDE_PATH pango/pango.h
    ${_PANGOIncDir}
    /opt/gnome/include/pango-1.0
    /usr/include/pango-1.0
  )

  PKGCONFIG(gdk-2.0 _GDK2IncDir _GDK2inkDir _GDK2LinkFlags _GDK2Cflags)
  FIND_PATH(GTK2_gdkconfig_INCLUDE_PATH gdkconfig.h
    ${_GDK2IncDir}
    /opt/gnome/lib/gtk-2.0/include
    /opt/gnome/lib64/gtk-2.0/include
    /usr/lib/gtk-2.0/include
    /usr/lib64/gtk-2.0/include
  )

  PKGCONFIG(cairo _CAIROIncDir _CAIROinkDir _CAIROLinkFlags _CAIROCflags)
  FIND_PATH(GTK2_cairo_INCLUDE_PATH cairo.h
    ${_CAIROIncDir}
    /opt/gnome/include/cairo
    /usr/include
    /usr/include/cairo )
  #MESSAGE("GTK2_cairo_INCLUDE_PATH = ${GTK2_cairo_INCLUDE_PATH}")

  PKGCONFIG(atk _ATKIncDir _ATKinkDir _ATKLinkFlags _ATKCflags)
  FIND_PATH(GTK2_atk_INCLUDE_PATH atk/atk.h
    ${_ATKIncDir}
    /opt/gnome/include/atk-1.0
    /usr/include/atk-1.0
  )
  #MESSAGE("GTK2_atk_INCLUDE_PATH = ${GTK2_atk_INCLUDE_PATH}")

  FIND_LIBRARY( GTK2_gtkgl_LIBRARY gtkgl
    ${_GTK2IncDir}
    /usr/lib
    /usr/local/lib
    /usr/openwin/lib
    /usr/X11R6/lib
    /opt/gnome/lib
  )

  #
  # The 12 suffix is thanks to the FreeBSD ports collection
  #

  FIND_LIBRARY(GTK2_gtk_LIBRARY
    NAMES  gtk-x11-2.0
    PATHS ${_GTK2LinkDir}
          /usr/lib
          /usr/local/lib
          /usr/openwin/lib
          /usr/X11R6/lib
          /opt/gnome/lib
  )

  FIND_LIBRARY( GTK2_gdk_LIBRARY
    NAMES  gdk-x11-2.0
    PATHS  ${_GDK2LinkDir}
           /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GTK2_gmodule_LIBRARY
    NAMES  gmodule-2.0
    PATHS  ${_GMODULE2inkDir}
           /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GTK2_glib_LIBRARY
    NAMES  glib-2.0
    PATHS  ${_GLIB2inkDir}
           /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GTK2_Xi_LIBRARY 
    NAMES Xi 
    PATHS /usr/lib 
    /usr/local/lib 
    /usr/openwin/lib 
    /usr/X11R6/lib 
    /opt/gnome/lib 
    ) 

  FIND_LIBRARY( GTK2_gthread_LIBRARY
    NAMES  gthread-2.0
    PATHS  /usr/lib
           /usr/local/lib
           /usr/openwin/lib
           /usr/X11R6/lib
           /opt/gnome/lib
  )

  FIND_LIBRARY( GTK2_gobject_LIBRARY
    NAMES  gobject-2.0
    PATHS 
           /opt/gnome/lib
  )

  IF(GTK2_gtk_INCLUDE_PATH)
  IF(GTK2_glibconfig_INCLUDE_PATH)
  IF(GTK2_glib_INCLUDE_PATH)
  IF(GTK2_gtk_LIBRARY)
  IF(GTK2_glib_LIBRARY)
  IF(GTK2_pango_INCLUDE_PATH)
    IF(GTK2_atk_INCLUDE_PATH)
      IF(GTK2_cairo_INCLUDE_PATH)
	# Assume that if gtk and glib were found, the other
	# supporting libraries have also been found.
	
	SET( GTK2_FOUND TRUE )
	SET( GTK2_INCLUDE_DIR  ${GTK2_gtk_INCLUDE_PATH}
          ${GTK2_glibconfig_INCLUDE_PATH}
          ${GTK2_glib_INCLUDE_PATH}
	  ${GTK2_pango_INCLUDE_PATH}
	  ${GTK2_gdkconfig_INCLUDE_PATH}
	  ${GTK2_atk_INCLUDE_PATH}
	  ${GTK2_cairo_INCLUDE_PATH})
	SET( GTK2_LIBRARIES  ${GTK2_gtk_LIBRARY}
          ${GTK2_gdk_LIBRARY}
          ${GTK2_glib_LIBRARY} )
	#${GTK2_gobject_LIBRARY})
    
      IF(GTK2_gmodule_LIBRARY)
	SET(GTK2_LIBRARIES ${GTK2_LIBRARIES} ${GTK2_gmodule_LIBRARY})
      ENDIF(GTK2_gmodule_LIBRARY)
      IF(GTK2_gthread_LIBRARY)
        SET(GTK2_LIBRARIES ${GTK2_LIBRARIES} ${GTK2_gthread_LIBRARY})
      ENDIF(GTK2_gthread_LIBRARY)
    ELSE(GTK2_cairo_INCLUDE_PATH)
      MESSAGE("Can not find cairo")
    ENDIF(GTK2_cairo_INCLUDE_PATH)
  ELSE(GTK2_atk_INCLUDE_PATH)
    MESSAGE("Can not find atk")
  ENDIF(GTK2_atk_INCLUDE_PATH)

  ELSE(GTK2_pango_INCLUDE_PATH)
       MESSAGE("Can not find pango includes")
  ENDIF(GTK2_pango_INCLUDE_PATH)
  ELSE(GTK2_glib_LIBRARY)
       MESSAGE("Can not find glib lib")
  ENDIF(GTK2_glib_LIBRARY)
  ELSE(GTK2_gtk_LIBRARY)
       MESSAGE("Can not find gtk lib")
  ENDIF(GTK2_gtk_LIBRARY)
  ELSE(GTK2_glib_INCLUDE_PATH) 
   MESSAGE("Can not find glib includes")
  ENDIF(GTK2_glib_INCLUDE_PATH) 
  ELSE(GTK2_glibconfig_INCLUDE_PATH)
   MESSAGE("Can not find glibconfig")
  ENDIF(GTK2_glibconfig_INCLUDE_PATH)
  ELSE(GTK2_gtk_INCLUDE_PATH)
   MESSAGE("Can not find gtk includes")
  ENDIF(GTK2_gtk_INCLUDE_PATH)

  if (GTK2_FOUND)
    if (NOT GTK2_FIND_QUIETLY)
      message(STATUS "Found GTK: ${GTK2_LIBRARIES}")
    endif (NOT GTK2_FIND_QUIETLY)
  else (GTK2_FOUND)
    if (GTK2_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find GTK")
    endif (GTK2_FIND_REQUIRED)
  endif (GTK2_FOUND)


  MARK_AS_ADVANCED(
    GTK2_gdk_LIBRARY
    GTK2_glib_INCLUDE_PATH
    GTK2_glib_LIBRARY
    GTK2_glibconfig_INCLUDE_PATH
    GTK2_gmodule_LIBRARY
    GTK2_gthread_LIBRARY
    GTK2_Xi_LIBRARY
    GTK2_gtk_INCLUDE_PATH
    GTK2_gtk_LIBRARY
    GTK2_gtkgl_INCLUDE_PATH
    GTK2_gtkgl_LIBRARY
    GTK2_atk_INCLUDE_PATH
    GTK2_gdkconfig_INCLUDE_PATH
#   GTK2_gobject_LIBRARY
    GTK2_pango_INCLUDE_PATH 
  )

ELSE(UNIX)
  # MESSAGE("FindGTK2 is working on UNIX/LINUX, only!")
ENDIF(UNIX)

