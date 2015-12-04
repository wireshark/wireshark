#
# Find the Microsoft Visual C++ library DLLs.
# These are included with the full frontal (Professional, Enterprise) editions
# of Visual Studio but not Express.
#
#  MSVCR_DLL - Path to the redistributable DLLs.
#

set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
include(InstallRequiredSystemLibraries)

# CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS will likely give us a list of DLL
# paths containing spaces. We'll assume that they're all in the same
# directory and use it to create something that's easier to pass to
# NSIS.

set(MSVCR_DLL)
list(GET CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS 0 _msvcr_dll)
if(_msvcr_dll)
	get_filename_component(_msvcr_dir ${_msvcr_dll} DIRECTORY)
	set(MSVCR_DLL "${_msvcr_dir}/*.*")
	file(TO_NATIVE_PATH "${MSVCR_DLL}" MSVCR_DLL)
endif()
