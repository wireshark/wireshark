#
# $Id$
#

# Pick one or more variables from the Makefile.common file
# with a path relative to the current CMakeLists.txt and provide
# their values as cmake variables of identical names.

# Usage:
#	include(UseMakefileCommon)
#	VAR_FROM_MAKEFILE_COMMON( <PATH> <VAR-1> ... <VAR-N> )

function( VARS_FROM_MAKEFILE_COMMON _path_to_mc )
	file( READ
		${CMAKE_CURRENT_SOURCE_DIR}/${_path_to_mc}/Makefile.common
		_use_mc_content
	)

	# Fold long lines
	string( REGEX REPLACE
		"(\\\\\r?[\n^][ \t]*)"
		" "
		_use_mc_content
		"${_use_mc_content}"
	)

	foreach( _use_mc_varname ${ARGN} )
		string( REGEX MATCH
			".*${_use_mc_varname}[ \t]*=[ \t]*([^\n]*)\r?[\n].*"
			_use_mc_var
			"${_use_mc_content}"
		)
		set( _use_mc_var ${CMAKE_MATCH_1} )
		string( REGEX REPLACE
			"[ \t]+"
			";"
			_use_mc_var
			"${_use_mc_var}"
		)
		set ( ${_use_mc_varname} )
		foreach ( _v ${_use_mc_var} )
			string( REGEX MATCH "\\$\\((.*)\\)" _matchres "${_v}" )
			if ( _matchres)
				string ( REGEX REPLACE "\\$\\((.*)\\)" "${${CMAKE_MATCH_1}}" _new_val "${_v}" )
				list( APPEND ${_use_mc_varname} "${_new_val}" )
			else()
				list( APPEND ${_use_mc_varname} "${_v}" )
			endif()
		endforeach()
		set( ${_use_mc_varname} ${${_use_mc_varname}} PARENT_SCOPE )
	endforeach()
endfunction()

