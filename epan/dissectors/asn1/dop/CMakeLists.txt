# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME dop )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	${PROTOCOL_NAME}.asn
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
	"${CMAKE_CURRENT_BINARY_DIR}/../dap/dap-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../dsp/dsp-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../crmf/crmf-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509af/x509af-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509if/x509if-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509sat/x509sat-exp.cnf"
)

ASN2WRS()
