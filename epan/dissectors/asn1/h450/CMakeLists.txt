# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME h450 )

set( PROTO_OPT _EMPTY_ )

set( EXT_ASN_FILE_LIST
)

set( H450_ASN
	H4501-Supplementary-ServiceAPDU-Structure.asn
	Addressing-Data-Elements.asn
	H225-generic-parameters-definition.asn
	Manufacturer-specific-service-extension-definition.asn
	H4501-General-Error-List.asn
)

set( H450_OP_ASN
	Call-Transfer-Operations.asn
	Call-Diversion-Operations.asn
	Call-Hold-Operations.asn
	Call-Park-Pickup-Operations.asn
	Call-Waiting-Operations.asn
	Message-Waiting-Indication-Operations.asn
	Name-Operations.asn
	Call-Completion-Operations.asn
	Call-Offer-Operations.asn
	Call-Intrusion-Operations.asn
	Common-Information-Operations.asn
)

set( ASN_FILE_LIST
	${H450_ASN}
	${H450_OP_ASN}
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
	"${CMAKE_CURRENT_BINARY_DIR}/../h450-ros/h450-ros-exp.cnf"
)

ASN2WRS()
