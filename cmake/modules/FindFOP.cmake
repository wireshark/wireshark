#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(FOP_EXECUTABLE
  NAMES
    fop
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(FOP DEFAULT_MSG FOP_EXECUTABLE)

IF(${FOP_EXECUTABLE})
	SET(FOP_OPTS -Xmx256m)
	SET(FOP_EXECUTABLE FOP_OPTS=${FOP_OPTS} JAVA_OPTS=${FOP_OPTS} ${FOP_EXECUTABLE})
ENDIF()
MARK_AS_ADVANCED(FOP_EXECUTABLE)

