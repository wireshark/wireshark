message("Copying source files from ${PROJECT_SOURCE_DIR} to ${WS_SOURCE_DIR}")

# create destination dir
file(MAKE_DIRECTORY "${WS_SOURCE_DIR}")

# Copy all files in the state *as known by git*, respecting export-ignore in .gitattributes
execute_process(COMMAND "${GIT_EXECUTABLE}" checkout-index -a -f --prefix "${WS_SOURCE_DIR}/" WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")

# Generate the version.conf and put it in brand new source dir
execute_process(COMMAND "${GIT_EXECUTABLE}" describe WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}" OUTPUT_VARIABLE GIT_DESCRIBE)
file(WRITE "${WS_SOURCE_DIR}/version.conf" "git_description=${GIT_DESCRIBE}")
