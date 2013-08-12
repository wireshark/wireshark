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

include(UseMakefileCommon)
VARS_FROM_MAKEFILE_COMMON(
	"."
	PROTOCOL_NAME
	ASN_FILE_LIST
	EXTRA_DIST
	SRC_FILES
	A2W_FLAGS
	EXTRA_CNF
)

#message( STATUS "Values used in c1222\n PROTOCOL_NAME: ${PROTOCOL_NAME}\n ASN_FILE_LIST: ${ASN_FILE_LIST}\n EXTRA_DIST: ${EXTRA_DIST}\n SRC_FILES: ${SRC_FILES}\n A2W_FLAGS: ${A2W_FLAGS}\n")
#foreach(v2 ${EXTRA_DIST})
#  message(STATUS "::${v2}::")
#endforeach()

#set( PROTOCOL_NAME c1222 )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST
)

#set( ASN_FILE_LIST
#	${PROTOCOL_NAME}.asn
#)

#set( EXTRA_DIST
#	${ASN_FILE_LIST}
#	packet-${PROTOCOL_NAME}-template.c
#	packet-${PROTOCOL_NAME}-template.h
#	${PROTOCOL_NAME}.cnf
#)

#set( SRC_FILES
#	${EXTRA_DIST}
#	${EXT_ASN_FILE_LIST}
#)

#set( A2W_FLAGS -b )

#set( EXTRA_CNF
#)

ASN2WRS()

