# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WSCODECS_PUBLIC_HEADERS
  codecs.h
)

set(WSCODECS_FILES
  codecs.c
  G711a/G711adecode.c
  G711u/G711udecode.c
  speex/resample.c
)

# Enables visibility in IDEs
file(GLOB EXTRA_CODEC_HEADERS
  codecs.h
  G711a/G711adecode.h G711a/G711atable.h
  G711u/G711udecode.h G711u/G711utable.h
  speex/arch.h
  speex/speex_resampler.h
  speex/stack_alloc.h
)

if(SBC_FOUND)
  set(WSCODECS_FILES ${WSCODECS_FILES} sbc/sbc.c)
endif()

set(wscodecs_LIBS
  ${M_LIBRARIES}
  ${GMODULE2_LIBRARIES}
  ${SBC_LIBRARIES}
  wsutil
)

if(HAVE_SPANDSP)
  list(APPEND WSCODECS_FILES G722/G722decode.c G726/G726decode.c)
  list(APPEND wscodecs_LIBS ${SPANDSP_LIBRARIES})
endif()

if(HAVE_BCG729)
  list(APPEND WSCODECS_FILES G729/G729decode.c)
  list(APPEND wscodecs_LIBS ${BCG729_LIBRARIES})
endif()

add_library(wscodecs
  ${WSCODECS_FILES}
  ${CMAKE_BINARY_DIR}/image/libwscodecs.rc
)

set(FULL_SO_VERSION "0.0.0")

set_target_properties(wscodecs PROPERTIES
  PREFIX "lib"
  COMPILE_DEFINITIONS "WS_BUILD_DLL"
  LINK_FLAGS "${WS_LINK_FLAGS}"
  VERSION ${FULL_SO_VERSION} SOVERSION 0
  FOLDER "DLLs"
)

if(ENABLE_APPLICATION_BUNDLE)
  set_target_properties(wscodecs PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Frameworks
  )
endif()

target_link_libraries(wscodecs ${wscodecs_LIBS})

install(TARGETS wscodecs
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(NOT WIN32)
  install(FILES ${WSCODECS_PUBLIC_HEADERS}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CPACK_PACKAGE_NAME}/codecs"
  )
endif()

CHECKAPI(
	NAME
	  codecs
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${WSCODECS_FILES}
)
