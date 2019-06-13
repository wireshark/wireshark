# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ADD_CUSTOM_CMAKE_INCLUDE()

set(ASN1_SRC_DIRS
	HI2Operations
	acp133
	acse
	ain
	ansi_map
	ansi_tcap
	atn-cm
	atn-cpdlc
	atn-ulcs
	c1222
	camel
	cbrs-oids
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
	e1ap
	ess
	f1ap
	ftam
	glow
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
	ieee1609dot2
	ilp
	inap
	isdn-sup
	its
	kerberos
	lcsap
	ldap
	lnpdqp
	logotypecertextn
	lpp
	lppa
	lppe
	lte-rrc
	m2ap
	m3ap
	mms
	mpeg-audio
	mpeg-pes
	mudurl
	nbap
	ngap
	nist-csor
	nr-rrc
	nrppa
	ns_cert_exts
	novell_pkis
	ocsp
	p1
	p22
	p7
	p772
	pcap
	pkcs1
	pkcs10
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
	tcg-cp-oids
	tetra
	ulp
	wlancertextn
	x2ap
	x509af
	x509ce
	x509if
	x509sat
	xnap
	z3950
	${CUSTOM_ASN1_SRC_DIR}
)

set( BROKEN_ASN1_SRC_DIRS
	# x721 does not build
	x721
)

set(_asn1_deps)
foreach(ASN1_DIR ${ASN1_SRC_DIRS})
	add_subdirectory( ${ASN1_DIR} )
	list(APPEND _asn1_deps ${ASN1_DIR}/generate_dissector-${ASN1_DIR})
endforeach()

# Target to regenerate all outdated ASN.1 dissectors
add_custom_target(asn1 DEPENDS ${_asn1_deps})
