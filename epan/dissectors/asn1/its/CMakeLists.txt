# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME its )

set( PROTO_OPT -o its )

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	ITS-Container.asn
	ITS-ContainerV1.asn
	ISO_TS_14816.asn
	ISO_TS_24534-3.asn
	ISO_TS_17419.asn
	ISO_TS_14906_Application.asn
	ISO_TS_19091.asn
	GDD.asn
	ISO19321IVIv2.asn
	ETSI_TS_103301.asn
	CAMv1.asn
	CAM.asn
	DENMv1.asn
	DENM.asn
	TIS_TPG_Transactions_Descriptions.asn
	EVCSN-PDU-Descriptions.asn
	EV-RSR-PDU-Descriptions.asn
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

ASN2WRS()
