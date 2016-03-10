# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

set( PROTOCOL_NAME camel )

set( PROTO_OPT )

set( EXT_ASN_FILE_LIST
)

set( EXT_ASN_FILE_LIST_LATE
	../ros/Remote-Operations-Information-Objects.asn
	../ros/Remote-Operations-Generic-ROS-PDUs.asn
)

set( ASN_FILE_LIST
	CAP-object-identifiers.asn
	CAP-classes.asn
	CAP-datatypes.asn
	CAP-errorcodes.asn
	CAP-errortypes.asn
	CAP-operationcodes.asn
	CAP-GPRS-ReferenceNumber.asn
	CAP-gsmSCF-gsmSRF-ops-args.asn
	CAP-gsmSSF-gsmSCF-ops-args.asn
	CAP-gprsSSF-gsmSCF-ops-args.asn
	CAP-SMS-ops-args.asn
	CAP-U-ABORT-Data.asn
	CamelV2diff.asn
)

set( EXTRA_DIST
	${ASN_FILE_LIST}
	packet-${PROTOCOL_NAME}-template.c
	packet-${PROTOCOL_NAME}-template.h
	${PROTOCOL_NAME}.asn
	${PROTOCOL_NAME}.cnf
)

set( SRC_FILES
	${EXTRA_DIST}
	${EXT_ASN_FILE_LIST}
)

set( A2W_FLAGS -b -L )

set( EXTRA_CNF
	"${CMAKE_CURRENT_BINARY_DIR}/../inap/inap-exp.cnf"
	"${CMAKE_CURRENT_BINARY_DIR}/../gsm_map/gsm_map-exp.cnf"
)

ASN2WRS()
