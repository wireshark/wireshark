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

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(WSPYTHON_FILES
	wspy_register.c
	wspy_proto.c
)

set(wspython_LIBS
	${PYTHON_LIBRARIES}
)

add_library(wspython STATIC
	${WSPYTHON_FILES}
)

target_link_libraries(wspython ${wspython_LIBS})

install(PROGRAMS
		register-dissector.py
		wspy_dissector.py
		wspy_libws.py
	DESTINATION	
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}/python/${CPACK_PACKAGE_VERSION}
)


install(DIRECTORY
		wspy_dissectors
	DESTINATION	
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}/python/${CPACK_PACKAGE_VERSION}
        PATTERN ".svn" EXCLUDE
)

