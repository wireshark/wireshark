#
# - Find Kerberos
# Find the native Kerberos includes and library
#
#  KERBEROS_INCLUDE_DIRS  - where to find krb5.h, etc.
#  KERBEROS_DEFINITIONS   - -D and other compiler flags to use with krb5.
#  KERBEROS_LIBRARIES     - List of libraries when using krb5.
#  KERBEROS_LINK_FLAGS    - other linker flags to use with krb5.
#  KERBEROS_FOUND         - True if krb5 found.
#  KERBEROS_DLL_DIR       - (Windows) Path to the Kerberos DLLs.
#  KERBEROS_DLLS          - (Windows) List of required Kerberos DLLs.
#  HAVE_HEIMDAL_KERBEROS  - set if the Kerberos vendor is Heimdal
#  HAVE_MIT_KERBEROS      - set if the Kerberos vendor is MIT


if(KERBEROS_INCLUDE_DIRS)
  # Already in cache, be silent
  set(KERBEROS_FIND_QUIETLY TRUE)
endif()

include(FindWSWinLibs)
FindWSWinLibs("krb5-.*" "KERBEROS_HINTS")

if(NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(KERBEROS krb5 mit-krb5 heimdal-krb5)
endif()

if(KERBEROS_FOUND)
  #
  # Turn KERBEROS_CFLAGS_OTHER into KERBEROS_DEFINITIONS;
  # <XPREFIX>_DEFINITIONS really means "flags other than -I,
  # including both -D and other flags".
  #
  set(KERBEROS_DEFINITIONS "${KERBEROS_CFLAGS_OTHER}")

  #
  # KERBEROS_LIBRARIES is a list of library names, not library
  # paths, and KERBEROS_LIBRARY_DIRS is a list of -L flag
  # arguments.  Turn KERBEROS_LIBRARIES into a list of absolute
  # paths for libraries, by searching for the libraries in
  # directories including KERBEROS_LIBRARY_DIRS.
  #
  set(_kerberos_libraries "${KERBEROS_LIBRARIES}")
  set(KERBEROS_LIBRARIES "")
  foreach(_library ${_kerberos_libraries})
    #
    # Search for the library, using the library directories from
    # pkg_search_module as hints.
    #
    find_library(_abspath_${_library} NAMES ${_library}
                 HINTS ${KERBEROS_LIBDIR} ${KERBEROS_LIBRARY_DIRS})
    list(APPEND KERBEROS_LIBRARIES ${_abspath_${_library}})
  endforeach()
else()
  # Fallback detection if pkg-config files are not installed.
  # Note, this fallback will not add k5crypto and com_err libraries on Linux,
  # ensure that pkg-config files are installed for full support.
  find_path(KERBEROS_INCLUDE_DIR krb5.h
    HINTS
      "${KERBEROS_HINTS}/include"
  )

  set(KERBEROS_NAMES krb5 krb5_32 krb5_64)
  find_library(KERBEROS_LIBRARY NAMES ${KERBEROS_NAMES}
    HINTS
      "${KERBEROS_HINTS}/lib"
  )

  # handle the QUIETLY and REQUIRED arguments and set KERBEROS_FOUND to TRUE if
  # all listed variables are TRUE
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(KERBEROS DEFAULT_MSG KERBEROS_LIBRARY KERBEROS_INCLUDE_DIR)

  if(KERBEROS_FOUND)
    set(KERBEROS_LIBRARIES ${KERBEROS_LIBRARY})
    set(KERBEROS_INCLUDE_DIRS ${KERBEROS_INCLUDE_DIR})
  else()
    set(KERBEROS_LIBRARIES)
    set(KERBEROS_INCLUDE_DIRS)
  endif()
endif()

# Try to detect the installed Kerberos vendor, assume MIT if it was not Heimdal.
if(KERBEROS_FOUND)
  include(CheckSymbolExists)
  set(CMAKE_REQUIRED_INCLUDES ${KERBEROS_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LIBRARIES ${KERBEROS_LIBRARIES})
  #see also HAVE_HEIMDAL_KERBEROS in cmakeconfig.h.in
  check_symbol_exists("heimdal_version" "krb5.h" HAVE_HEIMDAL_KERBEROS)
  # see also HAVE_KRB5_PAC_VERIFY cmakeconfig.h.in
  check_symbol_exists("krb5_pac_verify" "krb5.h" HAVE_KRB5_PAC_VERIFY)
  # see also HAVE_KRB5_C_FX_CF2_SIMPLE in cmakeconfig.h.in
  check_symbol_exists("krb5_c_fx_cf2_simple" "krb5.h" HAVE_KRB5_C_FX_CF2_SIMPLE)
  set(CMAKE_REQUIRED_INCLUDES)
  set(CMAKE_REQUIRED_LIBRARIES)
  if(NOT HAVE_HEIMDAL_KERBEROS)
    set(HAVE_MIT_KERBEROS 1)
  endif()
endif()

if(WIN32)
  if(KERBEROS_FOUND)
    set(KERBEROS_DLL_DIR "${KERBEROS_HINTS}/bin"
      CACHE PATH "Path to the Kerberos DLLs"
    )
    file(GLOB _kerberos_dlls RELATIVE "${KERBEROS_DLL_DIR}"
      "${KERBEROS_DLL_DIR}/comerr??.dll"
      "${KERBEROS_DLL_DIR}/krb5_??.dll"
      "${KERBEROS_DLL_DIR}/k5sprt??.dll"
    )
    set(KERBEROS_DLLS ${_kerberos_dlls}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Kerberos DLL list"
    )
    mark_as_advanced(KERBEROS_DLL_DIR KERBEROS_DLLS)
  else()
    set(KERBEROS_DLL_DIR)
    set(KERBEROS_DLLS)
  endif()
endif()

mark_as_advanced(KERBEROS_LIBRARIES KERBEROS_INCLUDE_DIRS KERBEROS_DEFINITIONS)
