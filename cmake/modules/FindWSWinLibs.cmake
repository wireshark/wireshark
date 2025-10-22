#
# - Find WSWin Libs
#  Due to the layout of the Wireshark Win support libs,
#  CMake needs some support to find them
#
#  The function is passed the directory name to search for and the variable
#  to set in the callers scope.

function( FindWSWinLibs _WS_LIB_SEARCH_PATH _LIB_HINT_VAR )
  if(USE_REPOSITORY)
    if( ARGN )
      set( _PROJECT_LIB_DIR ${ARGN} )
    else()
      if (WIRESHARK_BASE_DIR)
        file( TO_CMAKE_PATH ${WIRESHARK_BASE_DIR} _ws_base_dir )
        set( _PROJECT_LIB_DIR "${_ws_base_dir}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs" )
	unset(_ws_base_dir)
      else()
        file( TO_CMAKE_PATH $ENV{WIRESHARK_LIB_DIR} _PROJECT_LIB_DIR )
      endif()
    endif()

    file( GLOB _SUBDIR "${_PROJECT_LIB_DIR}/*" )
    # We might be able to use $ENV{VSCMD_ARG_TGT_ARCH} here.

    foreach( _DIR ${_SUBDIR} )
      if( IS_DIRECTORY ${_DIR} )
        if( "${_DIR}" MATCHES ".*/${_WS_LIB_SEARCH_PATH}" )
          set(_vcpkg_dir "${_DIR}/installed/${WIRESHARK_TARGET_PLATFORM}-windows")
          if( IS_DIRECTORY "${_vcpkg_dir}")
            set( ${_LIB_HINT_VAR} ${_vcpkg_dir} PARENT_SCOPE )
          else()
            set( ${_LIB_HINT_VAR} ${_DIR} PARENT_SCOPE )
          endif()
        endif()
      endif()
    endforeach()
  endif()
endfunction()

# Add a single DLL
function(AddWSWinDLL _PKG_NAME _PKG_HINTS _DLL_GLOB)
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
    string(TOUPPER ${_PKG_NAME} _PKG_VAR)
    set ( ${_PKG_VAR}_DLL_DIR "${${_PKG_HINTS}}/bin"
      CACHE PATH "Path to ${_PKG_NAME} DLL"
    )
    file( GLOB _pkg_dll RELATIVE "${${_PKG_VAR}_DLL_DIR}"
      "${${_PKG_VAR}_DLL_DIR}/${_DLL_GLOB}.dll"
    )
    set ( ${_PKG_VAR}_DLL ${_pkg_dll}
      CACHE STRING "${_PKG_NAME} DLL file name"
    )
    file( GLOB _pkg_pdb RELATIVE "${${_PKG_VAR}_DLL_DIR}"
      "${${_PKG_VAR}_DLL_DIR}/${_DLL_GLOB}.pdb"
    )
    set ( ${_PKG_VAR}_PDB ${_pkg_pdb}
      CACHE STRING "${_PKG_NAME} PDB file name"
    )
    mark_as_advanced( ${_PKG_VAR}_DLL_DIR ${_PKG_VAR}_DLL ${_PKG_VAR}_PDB )
  else()
    set( ${_PKG_VAR}_DLL_DIR )
    set( ${_PKG_VAR}_DLL )
  endif()
endfunction()

# Add a list of DLLs
function(AddWSWinDLLS _PKG_NAME _PKG_HINTS) # ...DLL globs
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
    string(TOUPPER ${_PKG_NAME} _PKG_VAR)
    set ( ${_PKG_VAR}_DLL_DIR "${${_PKG_HINTS}}/bin"
      CACHE PATH "Path to ${_PKG_NAME} DLLs"
    )

    set (_pkg_dlls)
    set (_pkg_pdbs)
    foreach(_dll_glob ${ARGN})
      file( GLOB _pkg_dll RELATIVE "${${_PKG_VAR}_DLL_DIR}"
        "${${_PKG_VAR}_DLL_DIR}/${_dll_glob}.dll"
      )
      list(APPEND _pkg_dlls "${_pkg_dll}")
      file( GLOB _pkg_pdb RELATIVE "${${_PKG_VAR}_DLL_DIR}"
        "${${_PKG_VAR}_DLL_DIR}/${_dll_glob}.pdb"
      )
      list(APPEND _pkg_pdbs "${_pkg_pdb}")
    endforeach()

    set ( ${_PKG_VAR}_DLLS ${_pkg_dlls}
    CACHE FILEPATH "${_PKG_NAME} DLL list"
    )
    set ( ${_PKG_VAR}_PDBS ${_pkg_pdbs}
      CACHE FILEPATH "${_PKG_NAME} PDB list"
    )

    mark_as_advanced( ${_PKG_VAR}_DLL_DIR ${_PKG_VAR}_DLLS ${_PKG_VAR}_PDBS )
  else()
    set( ${_PKG_VAR}_DLL_DIR )
    set( ${_PKG_VAR}_DLLS )
    set( ${_PKG_VAR}_PDBS )
  endif()
endfunction()
