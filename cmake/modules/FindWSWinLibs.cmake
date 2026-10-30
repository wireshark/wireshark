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

    set(_package_dir)
    foreach( _DIR ${_SUBDIR} )
      if( IS_DIRECTORY ${_DIR} )
        if( "${_DIR}" MATCHES ".*/${_WS_LIB_SEARCH_PATH}" )
          set(_package_dir ${_DIR})
          set(_vcpkg_dir "${_DIR}/installed/${WIRESHARK_TARGET_PLATFORM}-windows")
          if( IS_DIRECTORY "${_vcpkg_dir}")
            set( ${_LIB_HINT_VAR} ${_vcpkg_dir} PARENT_SCOPE )
          else()
            set( ${_LIB_HINT_VAR} ${_DIR} PARENT_SCOPE )
          endif()
        endif()
      endif()
    endforeach()
    if(_package_dir)
      _ws_unset_stale_cache_entries("${_PROJECT_LIB_DIR}" "${_WS_LIB_SEARCH_PATH}" "${_package_dir}")
    endif()
  endif()
endfunction()

# Unset the cache entries that point into a directory of another version of
# the package in package_dir, e.g. because the package was updated, so that
# the Find module looks for the package again. This catches all of the
# package's paths, whatever their variable names, without needing to
# delete CMakeCache.txt. Only entries created by find_*() or set(CACHE)
# are unset, not untyped ones given on the command line.
function(_ws_unset_stale_cache_entries libs_dir search_path package_dir)
  # Look at the cache entries that point into libs_dir as they were when
  # we started. Entries added since then point to current packages.
  get_property(_snapshot_taken GLOBAL PROPERTY _WS_LIBS_CACHE_ENTRIES SET)
  if(NOT _snapshot_taken)
    set(_entries)
    get_cmake_property(_cache_vars CACHE_VARIABLES)
    foreach(_var IN LISTS _cache_vars)
      get_property(_type CACHE ${_var} PROPERTY TYPE)
      if(_type MATCHES "^(FILEPATH|PATH|STRING)$")
        get_property(_value CACHE ${_var} PROPERTY VALUE)
        string(FIND "${_value}" "${libs_dir}/" _pos)
        if(NOT _pos EQUAL -1)
          list(APPEND _entries ${_var})
        endif()
      endif()
    endforeach()
    set_property(GLOBAL PROPERTY _WS_LIBS_CACHE_ENTRIES ${_entries})
  endif()

  get_property(_entries GLOBAL PROPERTY _WS_LIBS_CACHE_ENTRIES)
  string(LENGTH "${libs_dir}/" _prefix_len)
  set(_unset_vars)
  foreach(_var IN LISTS _entries)
    if(NOT DEFINED CACHE{${_var}})
      continue()
    endif()
    get_property(_value CACHE ${_var} PROPERTY VALUE)
    foreach(_item IN LISTS _value)
      string(FIND "${_item}" "${libs_dir}/" _pos)
      if(NOT _pos EQUAL 0)
        continue()
      endif()
      string(SUBSTRING "${_item}" ${_prefix_len} -1 _subpath)
      string(REGEX REPLACE "/.*" "" _subdir "${_subpath}")
      if("${libs_dir}/${_subdir}" MATCHES ".*/${search_path}"
          AND NOT "${libs_dir}/${_subdir}" STREQUAL package_dir)
        unset(${_var} CACHE)
        list(APPEND _unset_vars ${_var})
        break()
      endif()
    endforeach()
  endforeach()
  if(_unset_vars)
    get_filename_component(_package_name "${package_dir}" NAME)
    list(JOIN _unset_vars ", " _unset_vars)
    message(STATUS "Using ${_package_name}, clearing cached paths to other versions: ${_unset_vars}")
  endif()
endfunction()

# Unset the cached results of checks that depend on a package if the
# package has changed since they were run, so that they run again.
#
# ws_reset_checks_on_change(<name> <value identifying the package> <check result variables...>)
#
# The value would typically be the package's include directory and
# libraries. The checks are also run again the first time this is called.
function(ws_reset_checks_on_change _name _key)
  set(_state_var _WS_CHECKS_KEY_${_name})
  if(NOT DEFINED CACHE{${_state_var}} OR NOT "$CACHE{${_state_var}}" STREQUAL "${_key}")
    foreach(_var IN LISTS ARGN)
      unset(${_var} CACHE)
    endforeach()
  endif()
  set(${_state_var} "${_key}" CACHE INTERNAL "${_name} that the cached ${ARGN} checks used")
endfunction()

# Create a SHARED IMPORTED target for each third party DLL that we need at
# run time and register it in the WS_RUNTIME_DLL_TARGETS global property.
# The top-level CMakeLists.txt copies each registered DLL, along with its
# PDB if one is present, to the run directory and installs it.
#
# ws_add_runtime_dlls(<release DLL paths...> [DEBUG <debug DLL paths...>]
#                     [ONLY_FOR <application>])
#
# DEBUG lists the debug counterpart of each release DLL, in the same order,
# for packages that we link against debug import libraries in Debug builds.
# ONLY_FOR limits the DLLs to one application's installer, e.g. stratoshark.
# The targets are named ws_runtime::<DLL name> and do not have an import
# library, so they can't be linked against (yet).
function(ws_add_runtime_dlls)
  if(NOT USE_REPOSITORY)
    return()
  endif()
  cmake_parse_arguments(_ws "" "ONLY_FOR" "DEBUG" ${ARGN})
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
    set_target_properties(${_target} PROPERTIES
      IMPORTED_LOCATION "${_dll}"
      WS_RUNTIME_DLL_ONLY_FOR "${_ws_ONLY_FOR}"
    )
    if(_debug_dll AND EXISTS "${_debug_dll}")
      set_target_properties(${_target} PROPERTIES IMPORTED_LOCATION_DEBUG "${_debug_dll}")
    else()
      set_property(TARGET ${_target} PROPERTY IMPORTED_LOCATION_DEBUG)
    endif()
  endforeach()
endfunction()

# Get the file names of the DLLs registered with ws_add_runtime_dlls(), for
# an installer manifest. Names that are the same in Release and Debug builds
# go in <common_var>, the others in <release_var> and <debug_var>. Each list
# is sorted.
#
# ws_get_runtime_dll_names(<common_var> <release_var> <debug_var> FOR <application>)
#
# DLLs registered with ONLY_FOR are included only for that application.
function(ws_get_runtime_dll_names _common_var _release_var _debug_var)
  cmake_parse_arguments(_ws "" "FOR" "" ${ARGN})
  set(_common)
  set(_release)
  set(_debug)
  get_property(_targets GLOBAL PROPERTY WS_RUNTIME_DLL_TARGETS)
  foreach(_target IN LISTS _targets)
    get_target_property(_only_for ${_target} WS_RUNTIME_DLL_ONLY_FOR)
    if(_only_for AND NOT _only_for STREQUAL _ws_FOR)
      continue()
    endif()
    get_target_property(_location ${_target} IMPORTED_LOCATION)
    get_target_property(_location_debug ${_target} IMPORTED_LOCATION_DEBUG)
    get_filename_component(_name "${_location}" NAME)
    if(_location_debug)
      get_filename_component(_name_debug "${_location_debug}" NAME)
    else()
      set(_name_debug "${_name}")
    endif()
    if(_name STREQUAL _name_debug)
      list(APPEND _common "${_name}")
    else()
      list(APPEND _release "${_name}")
      list(APPEND _debug "${_name_debug}")
    endif()
  endforeach()
  foreach(_list _common _release _debug)
    list(SORT ${_list} CASE INSENSITIVE)
  endforeach()
  set(${_common_var} ${_common} PARENT_SCOPE)
  set(${_release_var} ${_release} PARENT_SCOPE)
  set(${_debug_var} ${_debug} PARENT_SCOPE)
endfunction()

# Add a single DLL. The debug DLL is used in Debug builds only if
# FindWSLibrary found a debug import library (<PKG>_LIBRARY_DEBUG).
#
# Sets <PKG>_DLL_DIR, <PKG>_DLL, <PKG>_PDB and their _DEBUG counterparts
# in the caller's scope. They aren't cached, so that they always match the
# package that was found.
function(AddWSWinDLL _PKG_NAME _PKG_HINTS _DLL_GLOB)
  string(TOUPPER ${_PKG_NAME} _PKG_VAR)
  set(_vars
    ${_PKG_VAR}_DLL_DIR ${_PKG_VAR}_DLL ${_PKG_VAR}_PDB
    ${_PKG_VAR}_DLL_DIR_DEBUG ${_PKG_VAR}_DLL_DEBUG ${_PKG_VAR}_PDB_DEBUG
  )
  # Remove the cache entries that we created before.
  foreach(_var IN LISTS _vars)
    unset(${_var} CACHE)
    set(${_var})
  endforeach()
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
    set(${_PKG_VAR}_DLL_DIR "${${_PKG_HINTS}}/bin")
    file( GLOB ${_PKG_VAR}_DLL RELATIVE "${${_PKG_VAR}_DLL_DIR}"
      "${${_PKG_VAR}_DLL_DIR}/${_DLL_GLOB}.dll"
    )
    file( GLOB ${_PKG_VAR}_PDB RELATIVE "${${_PKG_VAR}_DLL_DIR}"
      "${${_PKG_VAR}_DLL_DIR}/${_DLL_GLOB}.pdb"
    )
    set(${_PKG_VAR}_DLL_DIR_DEBUG "${${_PKG_HINTS}}/debug/bin")
    file( GLOB ${_PKG_VAR}_DLL_DEBUG RELATIVE "${${_PKG_VAR}_DLL_DIR_DEBUG}"
      "${${_PKG_VAR}_DLL_DIR_DEBUG}/${_DLL_GLOB}.dll"
    )
    file( GLOB ${_PKG_VAR}_PDB_DEBUG RELATIVE "${${_PKG_VAR}_DLL_DIR_DEBUG}"
      "${${_PKG_VAR}_DLL_DIR_DEBUG}/${_DLL_GLOB}.pdb"
    )

    list(TRANSFORM ${_PKG_VAR}_DLL PREPEND "${${_PKG_VAR}_DLL_DIR}/" OUTPUT_VARIABLE _release_dlls)
    set(_debug_dlls)
    if(${_PKG_VAR}_LIBRARY_DEBUG)
      list(TRANSFORM ${_PKG_VAR}_DLL_DEBUG PREPEND "${${_PKG_VAR}_DLL_DIR_DEBUG}/" OUTPUT_VARIABLE _debug_dlls)
    endif()
    ws_add_runtime_dlls(${_release_dlls} DEBUG ${_debug_dlls})
  endif()
  foreach(_var IN LISTS _vars)
    set(${_var} ${${_var}} PARENT_SCOPE)
  endforeach()
endfunction()

# Add a list of DLLs
#
# Sets <PKG>_DLL_DIR, <PKG>_DLLS and <PKG>_PDBS in the caller's scope.
# They aren't cached, so that they always match the package that was found.
function(AddWSWinDLLS _PKG_NAME _PKG_HINTS) # ...DLL globs
  string(TOUPPER ${_PKG_NAME} _PKG_VAR)
  set(_vars ${_PKG_VAR}_DLL_DIR ${_PKG_VAR}_DLLS ${_PKG_VAR}_PDBS)
  # Remove the cache entries that we created before.
  foreach(_var IN LISTS _vars)
    unset(${_var} CACHE)
    set(${_var})
  endforeach()
  if(USE_REPOSITORY AND ${_PKG_NAME}_FOUND)
    set(${_PKG_VAR}_DLL_DIR "${${_PKG_HINTS}}/bin")
    foreach(_dll_glob ${ARGN})
      file( GLOB _pkg_dll RELATIVE "${${_PKG_VAR}_DLL_DIR}"
        "${${_PKG_VAR}_DLL_DIR}/${_dll_glob}.dll"
      )
      list(APPEND ${_PKG_VAR}_DLLS ${_pkg_dll})
      file( GLOB _pkg_pdb RELATIVE "${${_PKG_VAR}_DLL_DIR}"
        "${${_PKG_VAR}_DLL_DIR}/${_dll_glob}.pdb"
      )
      list(APPEND ${_PKG_VAR}_PDBS ${_pkg_pdb})
    endforeach()

    list(TRANSFORM ${_PKG_VAR}_DLLS PREPEND "${${_PKG_VAR}_DLL_DIR}/" OUTPUT_VARIABLE _release_dlls)
    ws_add_runtime_dlls(${_release_dlls})
  endif()
  foreach(_var IN LISTS _vars)
    set(${_var} ${${_var}} PARENT_SCOPE)
  endforeach()
endfunction()
