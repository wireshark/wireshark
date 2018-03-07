# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME s1ap )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	S1AP-CommonDataTypes.asn
	S1AP-Constants.asn
	S1AP-Containers.asn
	S1AP-IEs.asn
	S1AP-PDU-Contents.asn
	S1AP-PDU-Descriptions.asn
	S1AP-SonTransfer-IEs.asn
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

set( A2W_FLAGS  )

ASN2WRS()
