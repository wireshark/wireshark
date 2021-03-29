#
# - Find Visual Leak Detector
#
#  VLD_LINK_FLAGS - MSVC linker flags that enable VLD
#  VLD_FILES - files that should be copied to dll output directory
#  VLD_VALID - TRUE if Visual Leak Detector was found

set(_PF86 "PROGRAMFILES(x86)")
set(_vld_arch Win64)
set(_vld_dll vld_x64.dll)
set(_vld_pdb vld_x64.pdb)
if(WIRESHARK_TARGET_PLATFORM MATCHES "win32")
	set(_vld_arch Win32)
	set(_vld_dll vld_x86.dll)
	set(_vld_pdb vld_x86.pdb)
endif()

find_library(VLD_LIBRARY
	NAMES
		vld
	HINTS
		"$ENV{PROGRAMFILES}/Visual Leak Detector/lib/${_vld_arch}"
		"$ENV{${_PF86}}/Visual Leak Detector/lib/${_vld_arch}"
		"$ENV{PROGRAMW6432}/Visual Leak Detector/lib/${_vld_arch}"
)

function(find_vld_file _vld_file _filename)
	find_file(${_vld_file}
		NAMES
			${_filename}
		HINTS
			"$ENV{PROGRAMFILES}/Visual Leak Detector/bin/${_vld_arch}"
			"$ENV{${_PF86}}/Visual Leak Detector/bin/${_vld_arch}"
			"$ENV{PROGRAMW6432}/Visual Leak Detector/bin/${_vld_arch}"
	)
	if(${${_vld_file}} STREQUAL "${_vld_file}-NOTFOUND")
		set(${_vld_file} "" PARENT_SCOPE)
	endif()
endfunction()

find_vld_file(VLD_DLL ${_vld_dll})
find_vld_file(VLD_DBGHELP_DLL "dbghelp.dll")
find_vld_file(VLD_MANIFEST "Microsoft.DTfW.DHL.manifest")
find_vld_file(VLD_PDB ${_vld_pdb})

#library, dlls and manifest are mandatory, while pdb is optional
IF(VLD_LIBRARY AND (EXISTS ${VLD_DLL}) AND (EXISTS ${VLD_DBGHELP_DLL}) AND (EXISTS ${VLD_MANIFEST}))
	# Link against VLD library and force it to be linked by referencing symbol
	# Adding VLD_LINK_FLAGS to linker flags enables Visual Leak Detector
	set(VLD_LINK_FLAGS "\"${VLD_LIBRARY}\" /include:__imp_?g_vld@@3VVisualLeakDetector@@A")
	file(GLOB VLD_FILES
		"${VLD_DLL}"
		"${VLD_DBGHELP_DLL}"
		"${VLD_MANIFEST}"
		"${VLD_PDB}"
	)
	set(VLD_FOUND TRUE)
else()
	set(VLD_LINK_FLAGS)
	set(VLD_FILES)
	set(VLD_FOUND FALSE)
endif()
