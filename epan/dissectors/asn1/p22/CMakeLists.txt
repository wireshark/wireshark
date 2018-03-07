# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME p22 )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	IPMSInformationObjects.asn
	IPMSHeadingExtensions.asn
	IPMSExtendedBodyPartTypes2.asn
	IPMSFileTransferBodyPartType.asn
	IPMSExtendedVoiceBodyPartType.asn
	IPMSForwardedContentBodyPartType.asn
	IPMSMessageStoreAttributes.asn
	IPMSSecurityExtensions.asn
	IPMSObjectIdentifiers.asn
	IPMSUpperBounds.asn
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

set( A2W_FLAGS -b -C )

set( EXTRA_CNF
	"${CMAKE_CURRENT_BINARY_DIR}/../acse/acse-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../ftam/ftam-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../p7/p7-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../p1/p1-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509af/x509af-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../x509ce/x509ce-exp.cnf"
)

set( EXPORT_DEPENDS
	"${CMAKE_CURRENT_BINARY_DIR}/../p1/p1-exp.cnf"
)

ASN2WRS()
