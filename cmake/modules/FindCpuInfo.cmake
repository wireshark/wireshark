#
# - Find cpuinfo
# Find CpuInfo includes and library
#
#  Creates an IMPORTED library target CpuInfo::CpuInfo
#  CpuInfo_FOUND     - True if CpuInfo found.
#
# Note that the library is static only on Windows, there is no DLL.
#
# On macOS there is no package in homebrew, the library needs to be
# built locally and will be found under /usr/local

include( FindWSWinLibs )
FindWSWinLibs( "cpuinfo-.*" "CPUINFO_HINTS" )

if( NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(CPUINFO libcpuinfo)
endif()

find_path(CPUINFO_INCLUDE_DIR
  NAMES cpuinfo.h
  HINTS "${CPUINFO_INCLUDEDIR}" "${CPUINFO_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(CPUINFO_LIBRARY
  NAMES cpuinfo
  HINTS "${CPUINFO_LIBDIR}" "${CPUINFO_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CpuInfo
    REQUIRED_VARS   CPUINFO_LIBRARY CPUINFO_INCLUDE_DIR)

if( CpuInfo_FOUND AND NOT TARGET CpuInfo::CpuInfo)
  # CpuInfo is static only on Windows - vcpkg says:
  # "On Windows, we can get a cpuinfo.dll, but it exports no symbols."
  add_library(CpuInfo::CpuInfo UNKNOWN IMPORTED)
  set_target_properties(CpuInfo::CpuInfo PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CPUINFO_INCLUDE_DIR}"
    IMPORTED_LOCATION "${CPUINFO_LIBRARY}"
  )
endif()
