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
      file( TO_CMAKE_PATH "$ENV{WIRESHARK_BASE_DIR}" _WS_BASE_DIR )
      set( _WS_TARGET_PLATFORM $ENV{WIRESHARK_TARGET_PLATFORM} )
      set( _PROJECT_LIB_DIR "${_WS_BASE_DIR}/wireshark-${_WS_TARGET_PLATFORM}-libs" )
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

# Massage the list of paths to external libraries to output a batch file to update the PATH
# So that running an executable can load the DLL's

function( WSExtendPath _LIB_PATH_LIST _PATH_FILE )
  if ( WIN32 )
    #message( STATUS "All libs: ${_LIB_PATH_LIST}." )
    # Convert each path that ends in "lib" to "bin" as linking requires the lib, running requires the dll.
    foreach( THIS_LIB_PATH ${_LIB_PATH_LIST} )
      if ( THIS_LIB_PATH MATCHES "[.]lib$" )
        # lib is required for linking, the dlls are in bin so fix the path
        # by chopping the library off the end and tacking "/bin" on
        get_filename_component( LIB_PATH ${THIS_LIB_PATH} PATH )
        string( REGEX REPLACE "/lib$" "/bin" LIB_PATH "${LIB_PATH}" )
      else()
        set ( LIB_PATH "${THIS_LIB_PATH}" )
      endif()
      #message( STATUS "Raw path ${THIS_LIB_PATH} processed to ${LIB_PATH}" )
      set( WS_LOCAL_LIB_PATHS "${WS_LOCAL_LIB_PATHS}" ${LIB_PATH} )
    endforeach()
    list( REMOVE_DUPLICATES WS_LOCAL_LIB_PATHS )
    # All generated libs go here, so start our libsearch in this place
    set( WS_LOCAL_LIB_PATHS "${CMAKE_BINARY_DIR}/lib" "${WS_LOCAL_LIB_PATHS}" )
    file( TO_NATIVE_PATH "${WS_LOCAL_LIB_PATHS}" WS_NATIVE_LIB_PATHS )
    if ( EXISTS ${_PATH_FILE} )
      file( READ ${_PATH_FILE} OLD_FILE_CONTENT )
    else()
      set( OLD_FILE_CONTENT " " )
    endif()
    #message( STATUS "Searching for ${WS_NATIVE_LIB_PATHS}\nin ${OLD_FILE_CONTENT}" )
    string( FIND "${OLD_FILE_CONTENT}" "${WS_NATIVE_LIB_PATHS}" PATH_FOUND_AT )
    #message( STATUS "Location of substr: ${PATH_FOUND_AT}" )
    if( PATH_FOUND_AT GREATER -1 )
      message( "\n${_PATH_FILE} is up to date.\n" )
    else()
      #message( STATUS "Native paths: ${WS_NATIVE_LIB_PATHS}" )
      file( WRITE ${_PATH_FILE} "set PATH=%PATH%;${WS_NATIVE_LIB_PATHS}" )
      message( "\n${_PATH_FILE} is new/updated, please run it.\n" )
    endif()
  endif()
endfunction()
