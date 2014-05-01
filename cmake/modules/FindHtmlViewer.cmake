#
# - Find an html viewer program
#
#  HTML_VIEWER_EXECUTABLE - the full path to perl
#  HTML_VIEWER_FOUND      - If false, don't attempt to use perl.

include( FindCygwin )

find_program( HTML_VIEWER_EXECUTABLE
  NAMES
    xdg-open
    mozilla
    htmlview
    open
    $ENV{HTML_VIEWER}
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

if( NOT HTML_VIEWER_EXECUTABLE AND WIN32 )
  foreach( _KEY
    [HKEY_CURRENT_USER\\Software\\Classes\\http\\shell\\open\\command]
    [HKEY_CLASSES_ROOT\\http\\shell\\open\\command]
  )
    get_filename_component( _NAME_WE ${_KEY} NAME_WE )
    get_filename_component( _PATH ${_KEY} PATH )
    string(REGEX REPLACE "\"" "" _NAME_WE ${_NAME_WE})
    string(REGEX REPLACE "\"" "" _PATH ${_PATH})
    find_program( HTML_VIEWER_EXECUTABLE "${_PATH}/${_NAME_WE}" NO_DEFAULT_PATH )
    if( HTML_VIEWER_EXECUTABLE )
      break()
    endif()
  endforeach()
endif()

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( HtmlViewer DEFAULT_MSG HTML_VIEWER_EXECUTABLE )

if (NOT HTML_VIEWER_EXECUTABLE)
    set(HTML_VIEWER_EXECUTABLE "")
    set(HTMLVIEWER_FOUND ON)
endif()

# For compat with configure
set( HTML_VIEWER ${HTML_VIEWER_EXECUTABLE} )

mark_as_advanced( HTML_VIEWER_EXECUTABLE )
