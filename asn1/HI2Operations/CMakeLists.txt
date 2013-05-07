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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

set( PROTOCOL_NAME HI2Operations )

set( ASN_FILE_LIST
	HI2Operations_ver11.asn
        UmtsHI2Operations.asn
        TS101909201.asn
        PCESP.asn
        EN301040.asn
)

set( SRC_FILES
        ${EXTRA_DIST}
        ${EXT_ASN_FILE_LIST}
)

set( A2W_FLAGS -b )

set( EXTRA_CNF
)

set( DISSECTOR ${CMAKE_SOURCE_DIR}/epan/dissectors/packet-${PROTOCOL_NAME}.c )

if ( NOT PROTO_OPT )
	set( PROTO_OPT -p ${PROTOCOL_NAME} )
endif()

# Don't use packet-${PROTOCOL_NAME}.c instead of generate_dissector, it will
# cause EXCLUDE_FROM_ALL to be ignored.
ADD_CUSTOM_TARGET(generate_dissector ALL
	COMMAND ${PYTHON_EXECUTABLE}
	  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
	  ${A2W_FLAGS}
	  ${PROTO_OPT}
	  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
	  -s ${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}-template
	  -D ${CMAKE_CURRENT_SOURCE_DIR}
	  -O ${CMAKE_SOURCE_DIR}/epan/dissectors
	  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
	DEPENDS
	  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
	  ${SRC_FILES}
	  ${EXTRA_CNF}
)

ADD_CUSTOM_TARGET(generate_export ALL
	COMMAND ${PYTHON_EXECUTABLE}
	  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
	  -E
	  ${A2W_FLAGS}
	  ${PROTO_OPT}
	  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
	  -D ${CMAKE_CURRENT_SOURCE_DIR}
	  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
	DEPENDS
	  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
	  ${SRC_FILES}
)

