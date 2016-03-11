# Add a target to call checkAPIs.pl on the specified source files
# The target is excluded from the ALL targte so must be manually
# specified in a build command.
# The target is added to the top-level checkAPIs target
#
# Parameters:
#   NAME: 	The name of the target, must be unique
#   SWITCHES:	Switches to be supplied to the script
#   SOURCES:	The sources to be checked

include(CMakeParseArguments)

macro( CHECKAPI )
	cmake_parse_arguments(CHECKAPI "DEBUG" "" "NAME;SWITCHES;SOURCES" ${ARGN} )

	if (CHECKAPI_UNPARSED_ARGUMENTS)
		message(FATAL_ERROR "CHECKAPIS Unknown argument: ${CHECKAPI_UNPARSED_ARGUMENTS}")
	endif()

	if( CHECKAPI_DEBUG )
		set (CHECKAPI_SWITCHES ${CHECKAPI_SWITCHES --debug)
	endif()

	set(TARGET_NAME checkAPI_${CHECKAPI_NAME})
	add_custom_target(${TARGET_NAME}
		COMMAND ${PERL_EXECUTABLE}
		  ${CMAKE_SOURCE_DIR}/tools/checkAPIs.pl
		  ${CHECKAPI_SWITCHES}
		  ${CHECKAPI_SOURCES}
		WORKING_DIRECTORY
		  ${CMAKE_CURRENT_SOURCE_DIR}
		COMMENT
		  "Running ${TARGET_NAME}"
	)
	add_dependencies(checkAPI ${TARGET_NAME})
	set_target_properties(${TARGET_NAME}
		PROPERTIES FOLDER "Auxiliary/CheckAPIs"
		EXCLUDE_FROM_ALL True
		EXCLUDE_FROM_DEFAULT_BUILD True
	)
ENDMACRO()
