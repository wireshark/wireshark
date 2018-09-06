# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME ain )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST_LATE
	../ros/Remote-Operations-Information-Objects.asn
	../ros/Remote-Operations-Generic-ROS-PDUs.asn
)


set( ASN_FILE_LIST
	AIN-Operations.asn
	AIN-Errors.asn
	AIN-Parameters.asn
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
