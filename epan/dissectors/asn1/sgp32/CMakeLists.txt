# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME sgp32 )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST )

set( ASN_FILE_LIST
	SGP32Definitions.asn
)

set( EXTRA_DIST
	${ASN_FILE_LIST}
	packet-${PROTOCOL_NAME}-template.c
	packet-${PROTOCOL_NAME}-template.h
	${PROTOCOL_NAME}.cnf
)

set( SRC_FILES
	${EXTRA_DIST}
	${EXT_ASN_FILE_LIST}
)

set( EXTRA_CNF
	../pkix1explicit/pkix1explicit_exp.cnf
	"${CMAKE_CURRENT_BINARY_DIR}/../pkix1implicit/pkix1implicit-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../sgp22/sgp22-exp.cnf"
)

set( A2W_FLAGS -b )

ASN2WRS()
