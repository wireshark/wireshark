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

set(DISSECTOR_SRC
	packet-mate.c
)

set(DISSECTOR_SUPPORT_SRC
	mate_setup.c
	mate_runtime.c
	mate_util.c
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

#mate_grammar.c : mate_grammar.lemon mate.h mate_util.h $(LEMON)/lemon$(EXEEXT)
#        $(LEMON)/lemon$(EXEEXT) t=$(srcdir)/$(LEMON)/lempar.c $(srcdir)/mate_grammar.lemon || \
#                (rm -f grammar.c grammar.h ; false)

add_lemon_files(DISSECTOR_SUPPORT_SRC
        mate_grammar.lemon
)

add_lex_files(DISSECTOR_SUPPORT_SRC
	mate_parser.l
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

# todo
# Do I need any of this or is this handled by type MODULE?
# asn1_la_LDFLAGS = -module -avoid-version

add_library(mate MODULE
	${PLUGIN_FILES}
)

target_link_libraries(mate epan)

install(TARGETS mate
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

