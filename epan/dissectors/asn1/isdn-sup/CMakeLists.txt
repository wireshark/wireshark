# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME isdn-sup )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	Addressing-Data-Elements.asn
	Basic-Service-Elements.asn
	Embedded-Q931-Types.asn
	General-Errors.asn
	Advice-of-Charge-Operations.asn
	Closed-User-Group-Service-Operations.asn
	Conference-Add-On-Operations.asn
	Diversion-Operations.asn
	MCID-Operations.asn
	User-To-User-Signalling-Operations.asn
	Freephone-Operations.asn
	MLPP-Operations-And-Errors.asn
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

set( A2W_FLAGS -b )

ASN2WRS()
