#
# $Id$
#
# - Find python libraries
# This module finds if Python is installed and determines where the
# include files and libraries are. It also determines what the name of
# the library is. This code sets the following variables:
#
#  PYTHON_FOUND     = have the Python libs been found
#  PYTHON_LIBRARIES     = path to the python library
#  PYTHON_INCLUDE_DIRS  = path to where Python.h is found
#

FIND_PROGRAM(CMAKE_PYTHON_CONFIG_EXECUTABLE
  NAMES
    python-config
  DOC
    "python-config executable"
  PATHS
    $ENV{PYTHON}
    $ENV{PYTHON}/bin
)

# check wether python-config was found:
IF(CMAKE_PYTHON_CONFIG_EXECUTABLE)
  EXEC_PROGRAM(${CMAKE_PYTHON_CONFIG_EXECUTABLE}
    ARGS
      --includes
    OUTPUT_VARIABLE
      PYTHON_CONFIG_INCLUDE_DIR
  )
  EXEC_PROGRAM(${CMAKE_PYTHON_CONFIG_EXECUTABLE}
    ARGS
      --libs
    OUTPUT_VARIABLE
      PYTHON_CONFIG_LIBRARIES
  )
  string(REGEX REPLACE
    "^ *-I"
    ""
    PYTHON_CONFIG_INCLUDE_DIR
    "${PYTHON_CONFIG_INCLUDE_DIR}"
  )
  string(REGEX REPLACE
    "^ *-l"
    ""
    PYTHON_CONFIG_LIBRARIES
    "${PYTHON_CONFIG_LIBRARIES}"
  ) 
  string(REGEX REPLACE
    " +-I"
    ";"
    PYTHON_INCLUDE_DIR
    "${PYTHON_CONFIG_INCLUDE_DIR}"
  )
  string(REGEX REPLACE
    " +-l"
    ";"
    PYTHON_LIBRARY
    "${PYTHON_CONFIG_LIBRARIES}"
  ) 
ELSE(CMAKE_PYTHON_CONFIG_EXECUTABLE)
  INCLUDE(CMakeFindFrameworks)
  # Search for the python framework on Apple.
  CMAKE_FIND_FRAMEWORKS(Python)
  
  FOREACH(_CURRENT_VERSION 2.6 2.5 2.4 2.3 2.2 2.1 2.0 1.6 1.5)
    STRING(REPLACE "." "" _CURRENT_VERSION_NO_DOTS ${_CURRENT_VERSION})

    FIND_LIBRARY(PYTHON_LIBRARY
      NAMES python${_CURRENT_VERSION_NO_DOTS} python${_CURRENT_VERSION}
      PATHS
        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_CURRENT_VERSION}\\InstallPath]/libs
      PATH_SUFFIXES
        python${_CURRENT_VERSION}/config
    )
  
    SET(PYTHON_FRAMEWORK_INCLUDES)
    IF(Python_FRAMEWORKS AND NOT PYTHON_INCLUDE_DIR)
      FOREACH(dir ${Python_FRAMEWORKS})
        SET(PYTHON_FRAMEWORK_INCLUDES ${PYTHON_FRAMEWORK_INCLUDES}
          ${dir}/Versions/${_CURRENT_VERSION}/include/python${_CURRENT_VERSION})
      ENDFOREACH(dir)
    ENDIF(Python_FRAMEWORKS AND NOT PYTHON_INCLUDE_DIR)
  
    FIND_PATH(PYTHON_INCLUDE_DIR
      NAMES Python.h
      PATHS
        ${PYTHON_FRAMEWORK_INCLUDES}
        [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_CURRENT_VERSION}\\InstallPath]/include
      PATH_SUFFIXES
        python${_CURRENT_VERSION}
    )
    
  ENDFOREACH(_CURRENT_VERSION)
ENDIF(CMAKE_PYTHON_CONFIG_EXECUTABLE)

# Python Should be built and installed as a Framework on OSX
IF(Python_FRAMEWORKS)
  # If a framework has been selected for the include path,
  # make sure "-framework" is used to link it.
  IF("${PYTHON_INCLUDE_DIR}" MATCHES "Python\\.framework")
    SET(PYTHON_LIBRARY "")
  ENDIF("${PYTHON_INCLUDE_DIR}" MATCHES "Python\\.framework")
  IF(NOT PYTHON_LIBRARY)
    SET (PYTHON_LIBRARY "-framework Python" CACHE FILEPATH "Python Framework" FORCE)
  ENDIF(NOT PYTHON_LIBRARY)
ENDIF(Python_FRAMEWORKS)

MARK_AS_ADVANCED(
  PYTHON_LIBRARIES
  PYTHON_INCLUDE_DIRS
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PYTHON DEFAULT_MSG PYTHON_LIBRARY PYTHON_INCLUDE_DIR)

IF(PYTHON_FOUND)
  SET( PYTHON_LIBRARIES ${PYTHON_LIBRARY} )
  SET( PYTHON_INCLUDE_DIRS ${PYTHON_INCLUDE_DIR} )
ELSE(PYTHON_FOUND)
  SET( PYTHON_LIBRARIES )
  SET( PYTHON_INCLUDE_DIRS )
ENDIF(PYTHON_FOUND)

# PYTHON_ADD_MODULE(<name> src1 src2 ... srcN) is used to build modules for python.
# PYTHON_WRITE_MODULES_HEADER(<filename>) writes a header file you can include 
# in your sources to initialize the static python modules

GET_PROPERTY(_TARGET_SUPPORTS_SHARED_LIBS
  GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS)

FUNCTION(PYTHON_ADD_MODULE _NAME )
  OPTION(PYTHON_ENABLE_MODULE_${_NAME} "Add module ${_NAME}" TRUE)
  OPTION(PYTHON_MODULE_${_NAME}_BUILD_SHARED "Add module ${_NAME} shared" ${_TARGET_SUPPORTS_SHARED_LIBS})

  IF(PYTHON_ENABLE_MODULE_${_NAME})
    IF(PYTHON_MODULE_${_NAME}_BUILD_SHARED)
      SET(PY_MODULE_TYPE MODULE)
    ELSE(PYTHON_MODULE_${_NAME}_BUILD_SHARED)
      SET(PY_MODULE_TYPE STATIC)
      SET_PROPERTY(GLOBAL  APPEND  PROPERTY  PY_STATIC_MODULES_LIST ${_NAME})
    ENDIF(PYTHON_MODULE_${_NAME}_BUILD_SHARED)

    SET_PROPERTY(GLOBAL  APPEND  PROPERTY  PY_MODULES_LIST ${_NAME})
    ADD_LIBRARY(${_NAME} ${PY_MODULE_TYPE} ${ARGN})
#    TARGET_LINK_LIBRARIES(${_NAME} ${PYTHON_LIBRARIES})

  ENDIF(PYTHON_ENABLE_MODULE_${_NAME})
ENDFUNCTION(PYTHON_ADD_MODULE)

FUNCTION(PYTHON_WRITE_MODULES_HEADER _filename)

  GET_PROPERTY(PY_STATIC_MODULES_LIST  GLOBAL  PROPERTY PY_STATIC_MODULES_LIST)

  GET_FILENAME_COMPONENT(_name "${_filename}" NAME)
  STRING(REPLACE "." "_" _name "${_name}")
  STRING(TOUPPER ${_name} _name)

  SET(_filenameTmp "${_filename}.in")
  FILE(WRITE ${_filenameTmp} "/*Created by cmake, do not edit, changes will be lost*/\n")
  FILE(APPEND ${_filenameTmp} 
"#ifndef ${_name}
#define ${_name}

#include <Python.h>

#ifdef __cplusplus
extern \"C\" {
#endif /* __cplusplus */

")

  FOREACH(_currentModule ${PY_STATIC_MODULES_LIST})
    FILE(APPEND ${_filenameTmp} "extern void init${PYTHON_MODULE_PREFIX}${_currentModule}(void);\n\n")
  ENDFOREACH(_currentModule ${PY_STATIC_MODULES_LIST})

  FILE(APPEND ${_filenameTmp} 
"#ifdef __cplusplus
}
#endif /* __cplusplus */

")


  FOREACH(_currentModule ${PY_STATIC_MODULES_LIST})
    FILE(APPEND ${_filenameTmp} "int CMakeLoadPythonModule_${_currentModule}(void) \n{\n  static char name[]=\"${PYTHON_MODULE_PREFIX}${_currentModule}\"; return PyImport_AppendInittab(name, init${PYTHON_MODULE_PREFIX}${_currentModule});\n}\n\n")
  ENDFOREACH(_currentModule ${PY_STATIC_MODULES_LIST})

  FILE(APPEND ${_filenameTmp} "#ifndef EXCLUDE_LOAD_ALL_FUNCTION\nvoid CMakeLoadAllPythonModules(void)\n{\n")
  FOREACH(_currentModule ${PY_STATIC_MODULES_LIST})
    FILE(APPEND ${_filenameTmp} "  CMakeLoadPythonModule_${_currentModule}();\n")
  ENDFOREACH(_currentModule ${PY_STATIC_MODULES_LIST})
  FILE(APPEND ${_filenameTmp} "}\n#endif\n\n#endif\n")
  
# with CONFIGURE_FILE() cmake complains that you may not use a file created using FILE(WRITE) as input file for CONFIGURE_FILE()
  EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_filenameTmp}" "${_filename}" OUTPUT_QUIET ERROR_QUIET)

ENDFUNCTION(PYTHON_WRITE_MODULES_HEADER)
