# - Find packages bundled with Windows
#

IF(WIN32)

SET(WIRESHARK_TARGET_PLATFORM "win32" CACHE STRING "Target platform (only win32/win64)")
SET(WIRESHARK_LIBS "c:/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs" CACHE PATH "Base directory, where your libraries reside")

SET(GLIB_VERSION "2.0" CACHE PATH "GLib version")

# GLib
set(GLIB2_INCLUDE_DIRS
    ${WIRESHARK_LIBS}/glib/include/glib-${GLIB_VERSION}
    ${WIRESHARK_LIBS}/glib/lib/glib-${GLIB_VERSION}/include
)
set(GLIB2_LIBRARIES
    ${WIRESHARK_LIBS}/glib/lib/glib-${GLIB_VERSION}.lib
    ${WIRESHARK_LIBS}/glib/lib/gmodule-${GLIB_VERSION}.lib
    ${WIRESHARK_LIBS}/glib/lib/gobject-${GLIB_VERSION}.lib
    # XXX: Also include GThread lib for now
    ${WIRESHARK_LIBS}/glib/lib/gthread-${GLIB_VERSION}.lib
)

SET(WSWIN32_FOUND TRUE)
SET(WSWIN32_INCLUDE_DIRS ${GLIB2_INCLUDE_DIRS})
SET(WSWIN32_LIBRARIES ${GLIB2_LIBRARIES})

# show the GLIB2_INCLUDE_DIRS and GLIB2_LIBRARIES variables only in the advanced view
mark_as_advanced(GLIB2_INCLUDE_DIRS GLIB2_LIBRARIES)

ENDIF()
