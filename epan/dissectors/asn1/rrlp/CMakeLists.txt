# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME rrlp )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST
	../gsm_map/MAP-ExtensionDataTypes.asn
	../gsm_map/MAP-LCS-DataTypes.asn
)

set( ASN_FILE_LIST
	RRLP-Messages.asn
	RRLP-Components.asn
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
