# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME h450-ros )

set( PROTO_OPT -p h450.ros )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
	../ros/Remote-Operations-Information-Objects.asn
)

set( ASN_FILE_LIST
	Remote-Operations-Apdus.asn
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

set( EXTRA_CNF
	../ros/ros-inv.cnf
	../ros/ros-res.cnf
	../ros/ros-err.cnf
	../ros/ros-rej.cnf
)

ASN2WRS()
