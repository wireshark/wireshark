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

set( PROTOCOL_NAME qsig )

set( PROTO_OPT _EMPTY_ )

set( EXPORT_FILES
	${PROTOCOL_NAME}-exp.cnf
)

set( EXT_ASN_FILE_LIST
)

set( ASN_FILE_LIST
	General-Error-List.asn
	qsig-gf-ext.asn
	qsig-gf-gp.asn
	qsig-gf-ade.asn
	QSIG-NA.asn
	QSIG-CF.asn
	QSIG-PR.asn
	QSIG-CT.asn
	QSIG-CC.asn
	QSIG-CO.asn
	QSIG-DND.asn
	QSIG-CI.asn
	QSIG-AOC.asn
	QSIG-RE.asn
	SYNC-SIG.asn
	QSIG-CINT.asn
	QSIG-CMN.asn
	QSIG-CPI.asn
	QSIG-PUMR.asn
	QSIG-PUMCH.asn
	QSIG-SSCT.asn
	QSIG-WTMLR.asn
	QSIG-WTMCH.asn
	QSIG-WTMAU.asn
	QSIG-SD.asn
	QSIG-CIDL.asn
	QSIG-SMS.asn
	QSIG-MCR.asn
	QSIG-MCM.asn
	QSIG-MID.asn
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

