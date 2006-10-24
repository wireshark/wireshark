# - pkg-config module for CMake
#
# Defines the following macros:
#
#  PKGCONFIG_FOUND(package found)
#  PKGCONFIG(package includedir libdir linkflags cflags)
#  PKGCONFIG_VERSION(package version)
#  PKGCONFIG_DEFINITION(package definition)

# Calling PKGCONFIG_FOUND will fill into the argument the value of the package search's result
# e.g. PKGCONFIG_FOUND(libart-2.0 LIBART_FOUND)
#
# Calling PKGCONFIG_VERSION will fill the desired version into the argument,
# e.g. PKGCONFIG_VERSION(libart-2.0 LIBART_VERSION)
# Calling PKGCONFIG will fill the desired information into the 4 given arguments,
# e.g. PKGCONFIG(libart-2.0 LIBART_INCLUDE_DIR LIBART_LINK_DIR LIBART_LINK_FLAGS LIBART_CFLAGS)
# if pkg-config was NOT found or the specified software package doesn't exist, the
# variable will be empty when the function returns, otherwise they will contain the respective information
#
# Calling PKGCONFIG_VERSION will fill the desired version into the argument,
# e.g. PKGCONFIG_VERSION(libart-2.0 LIBART_VERSION)
#
# Calling PKGCONFIG_DEFINITION will fill the definition (e.g -D_REENTRANT) into the argument,
# e.g. PKGCONFIG_DEFINITION(libart-2.0 LIBART_DEFINITION)

FIND_PROGRAM(PKGCONFIG_EXECUTABLE NAMES pkg-config PATHS /usr/local/bin )

MACRO(PKGCONFIG _package _include_DIR _link_DIR _link_FLAGS _cflags)
# reset the variables at the beginning
  SET(${_include_DIR})
  SET(${_link_DIR})
  SET(${_link_FLAGS})
  SET(${_cflags})

# if pkg-config has been found
  IF(PKGCONFIG_EXECUTABLE)

    EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE} ARGS ${_package} --exists RETURN_VALUE _return_VALUE OUTPUT_VARIABLE _pkgconfigDevNull )

# and if the package of interest also exists for pkg-config, then get the information
    IF(NOT _return_VALUE)

      EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE} ARGS ${_package} --variable=includedir OUTPUT_VARIABLE ${_include_DIR} )

      EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE} ARGS ${_package} --variable=libdir OUTPUT_VARIABLE ${_link_DIR} )

      EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE} ARGS ${_package} --libs OUTPUT_VARIABLE ${_link_FLAGS} )

      EXEC_PROGRAM(${PKGCONFIG_EXECUTABLE} ARGS ${_package} --cflags OUTPUT_VARIABLE ${_cflags} )

    ENDIF(NOT _return_VALUE)

  ENDIF(PKGCONFIG_EXECUTABLE)

ENDMACRO(PKGCONFIG _include_DIR _link_DIR _link_FLAGS _cflags)



MACRO(PKGCONFIG_FOUND _package _pkgpath _found)
  # reset the variable at the beginning
  SET(${_found})

# if pkg-config has been found
  IF(PKGCONFIG_EXECUTABLE)
    SET(ENV{PKG_CONFIG_PATH} ${_pkgpath})
    EXECUTE_PROCESS(COMMAND ${PKGCONFIG_EXECUTABLE} --print-errors --exists ${_package} RESULT_VARIABLE _return_VALUE OUTPUT_VARIABLE _pkgconfigDevNull )
    
    IF(${_pkgconfigDevNull})
      MESSAGE(STATUS "${_pkgconfigDevNull}")
    ENDIF(${_pkgconfigDevNull})
    
    IF(NOT _return_VALUE)
      SET(${_found} "TRUE")
    ENDIF(NOT _return_VALUE)
  ENDIF(PKGCONFIG_EXECUTABLE)

ENDMACRO(PKGCONFIG_FOUND _package _pkgpath _found)


#TODO: doesn't work when pkgconfig returns multiples inlude path
MACRO(PKGCONFIG_INCLUDE_DIRS _package _pkgpath _include_dirs)
# reset the variable at the beginning
  SET(${_include_dirs})
  IF(PKGCONFIG_EXECUTABLE)
    SET(ENV{PKG_CONFIG_PATH} ${_pkgpath})
    EXECUTE_PROCESS(COMMAND ${PKGCONFIG_EXECUTABLE} --cflags-only-I ${_package} OUTPUT_VARIABLE include)
    STRING(REGEX REPLACE "-I/" "/" _include_dirs_temp ${include})
    STRING(REGEX REPLACE "[\n\r]" "" ${_include_dirs} ${_include_dirs_temp})
    #When the include directory is /usr/include, pkgconfig returns a space and a new line
    IF("${_include_dirs}" STREQUAL " ")
      SET(${_include_dirs} "/usr/include")
    ENDIF("${_include_dirs}" STREQUAL " ")
  ENDIF(PKGCONFIG_EXECUTABLE)
ENDMACRO(PKGCONFIG_INCLUDE_DIRS _package _pkgpath _include_dirs)

MACRO(PKGCONFIG_LIBRARY_DIR _package _pkgpath _library_dir)
# reset the variable at the beginning
  SET(${_library_dir})
  IF(PKGCONFIG_EXECUTABLE)
    SET(ENV{PKG_CONFIG_PATH} ${_pkgpath})
    EXECUTE_PROCESS(COMMAND ${PKGCONFIG_EXECUTABLE} --libs-only-L ${_package} OUTPUT_VARIABLE libraries)
    STRING(REGEX REPLACE "-L/" "/" _library_dirs_temp ${libraries})
    MESSAGE(STATUS "lib dir ${_library_dirs_temp} end")
    STRING(REGEX REPLACE "[\r\n]" "" ${_library_dir} ${_library_dirs_temp})
    #When the library directory is /usr/lib, pkgconfig returns an empty stringand a new line
    IF("${_library_dir}" STREQUAL " ")
      SET(${_library_dir} "/usr/lib")
    ENDIF("${_library_dir}" STREQUAL " ")
    MESSAGE(STATUS "lib dir ${${_library_dir}} end")
  ENDIF(PKGCONFIG_EXECUTABLE)
ENDMACRO(PKGCONFIG_LIBRARY_DIR _package _pkgpath _library_dir)

MACRO(PKGCONFIG_VERSION _package _pkgpath _version)
# reset the variable at the beginning
  SET(${_version})

  IF(PKGCONFIG_EXECUTABLE)
    SET(ENV{PKG_CONFIG_PATH} ${_pkgpath})
    EXECUTE_PROCESS(COMMAND ${PKGCONFIG_EXECUTABLE} --modversion ${_package} OUTPUT_VARIABLE version)
    STRING(REGEX REPLACE "[\n\r]" "" ${_version} ${version})
  ENDIF(PKGCONFIG_EXECUTABLE)

ENDMACRO(PKGCONFIG_VERSION _package _pkgpath _version)

MACRO(PKGCONFIG_DEFINITION _package _pkgpath _definition)
# reset the variable at the beginning
  SET(${_definition})

  IF(PKGCONFIG_EXECUTABLE)
    SET(ENV{PKG_CONFIG_PATH} ${_pkgpath})
    EXECUTE_PROCESS(COMMAND ${PKGCONFIG_EXECUTABLE} --cflags-only-other ${_package} OUTPUT_VARIABLE definition)
    STRING(REGEX REPLACE "[\n\r]" "" ${_definition} ${definition})
  ENDIF(PKGCONFIG_EXECUTABLE)

ENDMACRO(PKGCONFIG_DEFINITION _package _pkgpath _definition)

MARK_AS_ADVANCED(PKGCONFIG_EXECUTABLE)
