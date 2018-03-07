# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME ocsp )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	OCSP.asn
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

set( A2W_FLAGS -b )

set( EXTRA_CNF
	"${CMAKE_CURRENT_BINARY_DIR}/../x509af/x509af-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509ce/x509ce-exp.cnf"
)

ASN2WRS()
