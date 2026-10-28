#
# Copy third party DLLs, along with their PDBs if present, to a directory.
#
# Usage: cmake -D RUNTIME_DLL_LIST=<file> -D DESTINATION=<dir> -P CopyRuntimeDLLs.cmake
#
# RUNTIME_DLL_LIST is a file containing one DLL path per line. The top-level
# CMakeLists.txt generates it from the WS_RUNTIME_DLL_TARGETS global
# property; see ws_add_runtime_dlls() in FindWSWinLibs.cmake.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

file(STRINGS "${RUNTIME_DLL_LIST}" _dlls)
file(MAKE_DIRECTORY "${DESTINATION}")

foreach(_dll IN LISTS _dlls)
	get_filename_component(_dll_dir "${_dll}" DIRECTORY)
	get_filename_component(_dll_name "${_dll}" NAME)
	get_filename_component(_dll_name_wle "${_dll}" NAME_WLE)
	file(COPY_FILE "${_dll}" "${DESTINATION}/${_dll_name}" ONLY_IF_DIFFERENT)
	if(EXISTS "${_dll_dir}/${_dll_name_wle}.pdb")
		file(COPY_FILE "${_dll_dir}/${_dll_name_wle}.pdb" "${DESTINATION}/${_dll_name_wle}.pdb" ONLY_IF_DIFFERENT)
	endif()
endforeach()
