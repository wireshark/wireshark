# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set( PROTOCOL_NAME inap )

set( PROTO_OPT )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST_LATE
	../ros/Remote-Operations-Information-Objects.asn
	../ros/Remote-Operations-Generic-ROS-PDUs.asn
)

set( 1248_1_ASN_FILES
	IN-operationcodes.asn
	IN-object-identifiers.asn
	IN-common-datatypes.asn
)

set( 1248_2_ASN_FILES
	IN-SSF-SCF-datatypes.asn
	IN-SSF-SCF-ops-args.asn
)

set( 1248_3_ASN_FILES
	IN-SCF-SRF-datatypes.asn
	IN-SCF-SRF-ops-args.asn
)

set( 1248_CLASSES_ASN
	IN-common-classes.asn
	IN-SSF-SCF-Classes.asn
	IN-SCF-SRF-Classes.asn
)

set( ASN_FILE_LIST
	${1248_CLASSES_ASN}
	${1248_1_ASN_FILES}
	${1248_2_ASN_FILES}
	${1248_3_ASN_FILES}
	IN-errorcodes.asn
	IN-errortypes.asn
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
)

ASN2WRS()
