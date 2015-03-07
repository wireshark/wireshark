# Generate a wrapper for test.sh.

set(TEST_SH_OUTPUT ${TEST_SH_BIN_DIR}/test.sh)

if(WIN32)
	INCLUDE(FindCygwin)
	FIND_PROGRAM(CYGPATH_EXECUTABLE
			NAMES cygpath
			PATHS ${CYGWIN_INSTALL_PATH}/bin
	)
	if (NOT "${CYGPATH_EXECUTABLE}" STREQUAL "CYGPATH_EXECUTABLE-NOTFOUND")
			execute_process(
				COMMAND ${CYGPATH_EXECUTABLE} -u ${TEST_SH_BIN_DIR}
				OUTPUT_VARIABLE _cygwin_path
			)
			string(STRIP "${_cygwin_path}" _cygwin_path)
			set(TEST_SH_BIN_DIR ${_cygwin_path})
			execute_process(
				COMMAND ${CYGPATH_EXECUTABLE} -u ${TEST_SH_SRC_DIR}
				OUTPUT_VARIABLE _cygwin_path
			)
			string(STRIP "${_cygwin_path}" _cygwin_path)
			set(TEST_SH_SRC_DIR ${_cygwin_path})
	endif()
endif()

set(TEST_SH_EXEC ${TEST_SH_SRC_DIR}/test.sh)

file(WRITE ${TEST_SH_OUTPUT} "#!/bin/sh\n")
if(WIN32)
	file(APPEND ${TEST_SH_OUTPUT} "(set -o igncr) 2>/dev/null && set -o igncr; # comment is needed\n")
endif()
file(APPEND ${TEST_SH_OUTPUT} "# Exec wrapper for ${TEST_SH_EXEC}\n")
file(APPEND ${TEST_SH_OUTPUT} "WS_BIN_PATH=${TEST_SH_BIN_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "export WS_BIN_PATH\n")
file(APPEND ${TEST_SH_OUTPUT} "WS_QT_BIN_PATH=${TEST_SH_BIN_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "export WS_QT_BIN_PATH\n")
file(APPEND ${TEST_SH_OUTPUT} "cd ${TEST_SH_SRC_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "exec ${TEST_SH_EXEC} \"$@\"\n")

execute_process(COMMAND chmod a+x ${TEST_SH_OUTPUT})

message(STATUS "Generated ${TEST_SH_OUTPUT}")