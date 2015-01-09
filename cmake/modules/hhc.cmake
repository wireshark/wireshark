# hhc.exe returns 1 on success - which cmake instprets as failure in case
#  of add_custom_command.

# Params 0,1 and 2 are "cmake -P hhc.cmake"
set(_param ${CMAKE_ARGV3})

EXECUTE_PROCESS(
  COMMAND ${HHC_EXECUTABLE} ${_param}
)
