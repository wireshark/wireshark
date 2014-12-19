#LOCATE_PYTHON_MODULE(<module> [PATHS <path1> ... <pathN>] [REQUIRED])
#
# This function tries to find the given python module.
# If found the path is provided in <PY_<module> and <<module>_FOUND> is set to TRUE.
#
# After PATHS additional paths for python to search can be provided.
# When REQUIRED is set, the function will abort the cmake execution is the module is not found
function(LOCATE_PYTHON_MODULE module)
	find_package(PythonInterp)

	# Parse (additional) arguments
	set(options REQUIRED)
	set(multiValueArgs PATHS)
	cmake_parse_arguments(LPM "${options}" "" "${multiValueArgs}" ${ARGN})

	string(TOUPPER ${module} module_upper)
	if(NOT PY_${module_upper})

		if(LPM_PATHS)
			# Append LPM_PATHS to PYTHONPATH to search at provided location (first)
			file(TO_CMAKE_PATH "$ENV{PYTHONPATH}" CMAKE_PATH)
			list(INSERT CMAKE_PATH 0 ${LPM_PATHS})
			file(TO_NATIVE_PATH "${CMAKE_PATH}" NATIVE_PATH)
			if(UNIX)
				string(REPLACE ";" ":" NATIVE_PATH "${NATIVE_PATH}")
			endif(UNIX)
			set(ENV{PYTHONPATH} "${NATIVE_PATH}")
		endif(LPM_PATHS)

		# Use the (native) python impl module to find the location of the requested module
		execute_process(COMMAND "${PYTHON_EXECUTABLE}" "-c"
			"import imp; print(imp.find_module('${module}')[1])"
			RESULT_VARIABLE _${module}_status
			OUTPUT_VARIABLE _${module}_location
			ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

		if(NOT _${module}_status)
			set(PY_${module_upper} ${_${module}_location} CACHE STRING
				"Location of Python module ${module}")
			set(${module_upper}_FOUND TRUE)
			message(STATUS "Found python module ${module}: ${PY_${module_upper}}")
		else(NOT _${module}_status)
			set(${module_upper}_FOUND FALSE)
			if(LPM_REQUIRED)
				message(FATAL_ERROR "Could NOT find python module ${module}")
			else(LPM_REQUIRED)
				message(STATUS "Could NOT find python module ${module}")
			endif(LPM_REQUIRED)
		endif(NOT _${module}_status)
	endif(NOT PY_${module_upper})
endfunction(LOCATE_PYTHON_MODULE)
