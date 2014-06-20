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


set(ASN1_SRC_DIRS
	HI2Operations
	acp133
	acse
	ansi_map
	ansi_tcap
	atn-cm
	atn-cpdlc
	atn-ulcs
	c1222
	camel
	cdt
	charging_ase
	cmip
	cmp
	cms
	credssp
	crmf
	dap
	disp
	dop
	dsp
	ess
	ftam
	gnm
	goose
	gprscdr
	gsm_map
	h225
	h235
	h245
	h248
	h282
	h283
	h323
	h450
	h450-ros
	h460
	h501
	hnbap
	idmp
	ilp
	inap
	isdn-sup
	kerberos
	lcsap
	ldap
	logotypecertextn
	lpp
	lppa
	lppe
	lte-rrc
	m3ap
	mms
	mpeg-audio
	mpeg-pes
	nbap
	ns_cert_exts
	novell_pkis
	ocsp
	p1
	p22
	p7
	p772
	pcap
	pkcs1
	pkcs12
	pkinit
	pkix1explicit
	pkix1implicit
	pkixac
	pkixproxy
	pkixqualified
	pkixtsp
	pres
	q932
	q932-ros
	qsig
	ranap
	rnsap
	ros
	rrc
	rrlp
	rtse
	rua
	s1ap
	sabp
	sbc-ap
	smrse
	snmp
	spnego
	sv
	t124
	t125
	t38
	tcap
	tetra
	ulp
	wlancertextn
	x2ap
	x509af
	x509ce
	x509if
	x509sat
)

set( BROKEN_ASN1_SRC_DIRS
	# x721 does not build
	x721
)

foreach(ASN1_DIR ${ASN1_SRC_DIRS})
	add_subdirectory( ${ASN1_DIR} )
endforeach()

