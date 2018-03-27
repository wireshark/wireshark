#
# Set environment variables and execute a program.
# Attempts to emulate "cmake -E env" which is only available since CMake 3.1.
#
# Copyright 2018 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: MIT
#
# Usage:
#
#   cmake -P env.cmake [NAME=VALUE]... [COMMAND [ARG]...]
#
# Limitations due to CMake:
#
# - The command and arguments cannot be keywords for the "execute_process"
#   command ("COMMAND", "ENCODING", "TIMEOUT", "WORKING_DIRECTORY", etc.).
# - Empty arguments are ignored, arguments with a trailing backslash ("\") will
#   have the slash replaced by a forward slash ("/").
# - If a program fails, a message will be printed and exit code 1 is returned.

# Choose between two evils for the command line limitations:
# (1) Hard-coded number of maximum arguments and repetitive lines.
# (2) Limitations on the arguments (due to use of lists).
# (3) A combination of both.
# For simplicity, (2) is chosen here.
set(command)

math(EXPR argsCount "${CMAKE_ARGC} - 1")
set(skip_args ${argsCount})
set(maybe_env TRUE)

foreach(argNumber RANGE ${argsCount})
  set(arg "${CMAKE_ARGV${argNumber}}")

  if(skip_args EQUAL 0)
    # Escape ";" (list separator) to avoid splitting arguments.
    string(REPLACE ";" "\\;" argForList "${arg}")

    # Prevent a trailing backslash from escaping the next list separator.
    # Hopefully it is just a path separator, otherwise there will be problems.
    if(argForList MATCHES "(.*)\\\\$")
      message(WARNING "Trailing backslash is converted to forward slash in: ${arg}")
      set(argForList "${CMAKE_MATCH_1}/")
    endif()

    if(argForList STREQUAL "")
      message(WARNING "Empty arguments are currently not supported and ignored")
    endif()

    if(maybe_env)
      # Try to parse NAME=VALUE
      if(arg MATCHES "^([^=]+)=(.*)$")
        set("ENV{${CMAKE_MATCH_1}}" "${CMAKE_MATCH_2}")
      else()
        set(maybe_env FALSE)
        list(APPEND command "${argForList}")
      endif()
    else()
      # Definitely no more env vars.
      list(APPEND command "${argForList}")
    endif()
  else()
    # Skip arguments until "-P env.cmake" is found.
    if(arg STREQUAL "-P")
      # just skip "env.cmake" from now on
      set(skip_args 1)
    else()
      math(EXPR skip_args "${skip_args} - 1")
    endif()
  endif()
endforeach()

execute_process(COMMAND ${command} RESULT_VARIABLE exitCode)

if(NOT exitCode EQUAL 0)
  message(FATAL_ERROR "Process exited with ${exitCode}")
endif()
