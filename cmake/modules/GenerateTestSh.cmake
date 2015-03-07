# Generate a wrapper for test.sh.

set(TEST_SH_EXEC ${TEST_SH_DIR}/test.sh)
set(TEST_SH_OUTPUT ${TEST_SH_BIN_DIR}/test.sh)

file(WRITE ${TEST_SH_OUTPUT} "#!/bin/sh\n")
file(APPEND ${TEST_SH_OUTPUT} "# Exec wrapper for ${TEST_SH_EXEC}\n")
file(APPEND ${TEST_SH_OUTPUT} "WS_BIN_PATH=${TEST_SH_BIN_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "export WS_BIN_PATH\n")
file(APPEND ${TEST_SH_OUTPUT} "WS_QT_BIN_PATH=${TEST_SH_BIN_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "export WS_QT_BIN_PATH\n")
file(APPEND ${TEST_SH_OUTPUT} "cd ${TEST_SH_DIR}\n")
file(APPEND ${TEST_SH_OUTPUT} "exec ${TEST_SH_EXEC}\n")

execute_process(COMMAND chmod a+x ${TEST_SH_OUTPUT})

message(STATUS "Generated ${TEST_SH_OUTPUT}")