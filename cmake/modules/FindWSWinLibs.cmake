#
# - Find WSWin Libs
#  Due to the layout of the Wireshark Win support libs,
#  CMake needs some support to find them
#
#  The function is passed the directory name to search for and the variable
#  to set in the callers scope.

function( FindWSWinLibs _WS_LIB_SEARCH_PATH _LIB_HINT_VAR )
  if( WIN32 )
    if( ARGN )
      set( _PROJECT_LIB_DIR ${ARGN} )
    else()
      if( DEFINED ENV{WIRESHARK_LIB_DIR} )
        # The buildbots set WIRESHARK_LIB_DIR but not WIRESHARK_BASE_DIR.
        file( TO_CMAKE_PATH "$ENV{WIRESHARK_LIB_DIR}" _PROJECT_LIB_DIR )
      else()
        file( TO_CMAKE_PATH "$ENV{WIRESHARK_BASE_DIR}" _WS_BASE_DIR )
        set( _PROJECT_LIB_DIR "${_WS_BASE_DIR}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs-2.2" )
      endif()
    endif()
    file( GLOB _SUBDIR "${_PROJECT_LIB_DIR}/*" )
    foreach( _DIR ${_SUBDIR} )
      if( IS_DIRECTORY ${_DIR} )
        if( "${_DIR}" MATCHES ".*/${_WS_LIB_SEARCH_PATH}" )
          set( ${_LIB_HINT_VAR} ${_DIR} PARENT_SCOPE )
        endif()
      endif()
    endforeach()
  endif()
endfunction()
