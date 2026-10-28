#
# - Find WSWin Libs
#  Due to the layout of the Wireshark Win support libs,
#  CMake needs some support to find them
#
#  The function is passed the directory name to search for and the variable
#  to set in the callers scope.
#
# To do:
# pkgconf has a vcpkg port, and vcpkg ports ship with .pc files. We should
# add pkgconf to dev-libs and use it instead of this where possible.

function( FindWSWinLibs _WS_LIB_SEARCH_PATH _LIB_HINT_VAR )
  if(USE_REPOSITORY)
    if( ARGN )
      set( _PROJECT_LIB_DIR ${ARGN} )
    else()
      if (WIRESHARK_BASE_DIR)
        file( TO_CMAKE_PATH "${WIRESHARK_BASE_DIR}" _ws_base_dir )
        set( _PROJECT_LIB_DIR "${_ws_base_dir}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs" )
	unset(_ws_base_dir)
      else()
        file( TO_CMAKE_PATH "$ENV{WIRESHARK_LIB_DIR}" _PROJECT_LIB_DIR )
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

# Create a SHARED IMPORTED target for each third party DLL that we need at
# run time and register it in the WS_RUNTIME_DLL_TARGETS global property.
# The top-level CMakeLists.txt copies each registered DLL, along with its
# PDB if one is present, to the run directory and installs it.
#
# ws_add_runtime_dlls(<release DLL paths...> [DEBUG <debug DLL paths...>])
#
# DEBUG lists the debug counterpart of each release DLL, in the same order,
# for packages that we link against debug import libraries in Debug builds.
# The targets are named ws_runtime::<DLL name> and do not have an import
# library, so they can't be linked against (yet).
function(ws_add_runtime_dlls)
  if(NOT USE_REPOSITORY)
    return()
  endif()
  cmake_parse_arguments(_ws "" "" "DEBUG" ${ARGN})
  set(_release_dlls ${_ws_UNPARSED_ARGUMENTS})
  list(LENGTH _release_dlls _release_count)
  list(LENGTH _ws_DEBUG _debug_count)
  if(_debug_count AND NOT _debug_count EQUAL _release_count)
    message(WARNING "Ignoring debug DLLs ${_ws_DEBUG}: they don't match release DLLs ${_release_dlls}")
    set(_ws_DEBUG)
  endif()
  foreach(_dll _debug_dll IN ZIP_LISTS _release_dlls _ws_DEBUG)
    if(NOT EXISTS "${_dll}")
      continue()
    endif()
    get_filename_component(_dll_name "${_dll}" NAME_WLE)
    string(MAKE_C_IDENTIFIER "${_dll_name}" _dll_id)
    set(_target ws_runtime::${_dll_id})
    # Some DLLs, such as liblzma and zstd, are shipped by more than one
    # package. The last one found wins.
    if(NOT TARGET ${_target})
      add_library(${_target} SHARED IMPORTED GLOBAL)
      set_property(GLOBAL APPEND PROPERTY WS_RUNTIME_DLL_TARGETS ${_target})
    endif()
    set_target_properties(${_target} PROPERTIES IMPORTED_LOCATION "${_dll}")
    if(_debug_dll AND EXISTS "${_debug_dll}")
      set_target_properties(${_target} PROPERTIES IMPORTED_LOCATION_DEBUG "${_debug_dll}")
    else()
      set_property(TARGET ${_target} PROPERTY IMPORTED_LOCATION_DEBUG)
    endif()
  endforeach()
endfunction()

# Add a single DLL. The debug DLL is used in Debug builds only if
# FindWSLibrary found a debug import library (<PKG>_LIBRARY_DEBUG).
function(AddWSWinDLL _PKG_NAME _PKG_HINTS _DLL_GLOB)
  string(TOUPPER ${_PKG_NAME} _PKG_VAR)
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
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
    set ( ${_PKG_VAR}_DLL_DIR_DEBUG "${${_PKG_HINTS}}/debug/bin"
      CACHE PATH "Path to ${_PKG_NAME} Debug DLL"
    )
    file( GLOB _pkg_dll RELATIVE "${${_PKG_VAR}_DLL_DIR_DEBUG}"
      "${${_PKG_VAR}_DLL_DIR_DEBUG}/${_DLL_GLOB}.dll"
    )
    set ( ${_PKG_VAR}_DLL_DEBUG ${_pkg_dll}
      CACHE STRING "${_PKG_NAME} Debug DLL file name"
    )
    file( GLOB _pkg_pdb RELATIVE "${${_PKG_VAR}_DLL_DIR_DEBUG}"
      "${${_PKG_VAR}_DLL_DIR_DEBUG}/${_DLL_GLOB}.pdb"
    )
    set ( ${_PKG_VAR}_PDB_DEBUG ${_pkg_pdb}
      CACHE STRING "${_PKG_NAME} Debug PDB file name"
    )
    mark_as_advanced( ${_PKG_VAR}_DLL_DIR_DEBUG ${_PKG_VAR}_DLL_DEBUG ${_PKG_VAR}_PDB_DEBUG )

    list(TRANSFORM ${_PKG_VAR}_DLL PREPEND "${${_PKG_VAR}_DLL_DIR}/" OUTPUT_VARIABLE _release_dlls)
    set(_debug_dlls)
    if(${_PKG_VAR}_LIBRARY_DEBUG)
      list(TRANSFORM ${_PKG_VAR}_DLL_DEBUG PREPEND "${${_PKG_VAR}_DLL_DIR_DEBUG}/" OUTPUT_VARIABLE _debug_dlls)
    endif()
    ws_add_runtime_dlls(${_release_dlls} DEBUG ${_debug_dlls})
  else()
    set( ${_PKG_VAR}_DLL_DIR )
    set( ${_PKG_VAR}_DLL )
    set( ${_PKG_VAR}_PDB )
    set( ${_PKG_VAR}_DLL_DIR_DEBUG )
    set( ${_PKG_VAR}_DLL_DEBUG )
    set( ${_PKG_VAR}_PDB_DEBUG )
  endif()
endfunction()

# Add a list of DLLs
function(AddWSWinDLLS _PKG_NAME _PKG_HINTS) # ...DLL globs
  string(TOUPPER ${_PKG_NAME} _PKG_VAR)
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
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

    list(TRANSFORM ${_PKG_VAR}_DLLS PREPEND "${${_PKG_VAR}_DLL_DIR}/" OUTPUT_VARIABLE _release_dlls)
    ws_add_runtime_dlls(${_release_dlls})
  else()
    set( ${_PKG_VAR}_DLL_DIR )
    set( ${_PKG_VAR}_DLLS )
    set( ${_PKG_VAR}_PDBS )
  endif()
endfunction()
