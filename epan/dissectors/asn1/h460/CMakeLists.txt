# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME h460 )

set( PROTO_OPT _EMPTY_ )

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	NUMBER-PORTABILITY.asn
	CIRCUIT-STATUS-MAP.asn
	CALL-PRIORITY.asn
	QOS-MONITORING-REPORT.asn
	QOS-MONITORING-EXTENDED-VOIP-REPORT.asn
	CALL-PARTY-CATEGORY.asn
	MLPP.asn
	SIGNALLING-CHANNEL-SUSPEND-REDIRECT.asn
	SIGNALLING-TRAVERSAL.asn
	MEDIA-TRAVERSAL.asn
	MESSAGE-BROADCAST.asn
)

set( EXTRA_DIST
	${ASN_FILE_LIST}
	packet-${PROTOCOL_NAME}-template.c
	${PROTOCOL_NAME}.cnf
)

set( SRC_FILES
	${EXTRA_DIST}
	${EXT_ASN_FILE_LIST}
)

set( A2W_FLAGS  )

set( EXTRA_CNF
	"${CMAKE_CURRENT_BINARY_DIR}/../h225/h225-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../h235/h235-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../h245/h245-exp.cnf"
)

ASN2WRS()
