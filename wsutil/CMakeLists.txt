# CMakeLists.txt
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

IF(WIN32)
  set(WSUTIL_PLATFORM_FILES
    file_util.c
    unicode-utils.c
  )
ENDIF(WIN32)

set(WSUTIL_FILES
  mpeg-audio.c
  privileges.c
  str_util.c
  type_util.c
  ${WSUTIL_PLATFORM_FILES}
)

add_library(wsutil SHARED
  ${WSUTIL_FILES}
)

install(TARGETS wsutil
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION lib
    ARCHIVE DESTINATION lib)
