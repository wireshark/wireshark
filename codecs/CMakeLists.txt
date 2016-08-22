# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

set(WSCODECS_FILES
  codecs.c
  G711a/G711adecode.c
  G711u/G711udecode.c
  # These are wrapped in "#ifdef HAVE_SPANDSP", which we don't currently
  # handle or define.
  # G722/G722decode.c
  # G726/G726decode.c
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

add_library(wscodecs ${LINK_MODE_LIB}
  ${WSCODECS_FILES}
  ${CMAKE_BINARY_DIR}/image/libwscodecs.rc
)

set(FULL_SO_VERSION "1.0.0")

set_target_properties(wscodecs PROPERTIES
  PREFIX "lib"
  COMPILE_DEFINITIONS "WS_BUILD_DLL"
  LINK_FLAGS "${WS_LINK_FLAGS}"
  VERSION ${FULL_SO_VERSION} SOVERSION 1
  FOLDER "DLLs"
)

if(ENABLE_APPLICATION_BUNDLE)
  set_target_properties(wscodecs PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Frameworks
  )
endif()

target_link_libraries(wscodecs ${wscodecs_LIBS})

if(NOT ${ENABLE_STATIC})
  install(TARGETS wscodecs
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
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
