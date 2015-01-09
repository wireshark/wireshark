# hhc.exe returns 1 on success - which cmake instprets as failure in case
#  of add_custom_command.

# Params are
#   cmake -P /path/to/hhc.cmake "/path/to/hhc.exe" project.hhp
set(_hhc_executable ${CMAKE_ARGV3})
set(_project_file ${CMAKE_ARGV4})

execute_process(
  COMMAND ${_hhc_executable} ${_project_file}
  RESULT_VARIABLE _return_code
)
