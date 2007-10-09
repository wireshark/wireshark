# Makefile.am
# Automake file for Wireshark
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2006 Gerald Combs
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

SUBDIRS = \
	acp133		\
	acse		\
	ansi_map	\
	camel		\
	cdt		\
	cmip		\
	cms		\
	dap		\
	disp		\
	dop		\
	dsp		\
	ess		\
	ftam		\
	gnm		\
	gsmmap		\
	h225		\
	h235		\
	h245		\
	h248		\
	h450		\
	h450-ros	\
	inap		\
	ldap		\
	logotype-cert-extn	\
	mms		\
	mpeg-audio	\
	mpeg-pes	\
	nbap		\
	ns-cert-exts	\
	ocsp		\
	pkcs1		\
	pkcs12		\
	pkinit		\
	pkix1explicit	\
	pkix1implicit	\
	pkixcmp		\
	pkixcrmf	\
	pkixproxy	\
	pkixqualified	\
	pkixtsp		\
	pres		\
	qsig		\
	ranap		\
	rnsap		\
	rrc		\
	rrlp		\
	sabp		\
	t38		\
	ulp

EXTRA_DIST = \
	Makefile.nmake	\
	q932/Addressing-Data-Elements.asn	\
	q932/Interpretation-component.asn	\
	q932/Network-Facility-Extension.asn	\
	q932/Network-Protocol-Profile-component.asn	\
	q932/Facility-Information-Element-Components.asn	\
	q932/q932.cnf	\
	q932/q932-ros.cnf	\
	q932/q932-exp.cnf	\
	q932/Makefile	\
	q932/Makefile.nmake	\
	q932/packet-q932-ros-template.c	\
	q932/packet-q932-template.c	\
	q932/packet-q932-template.h	\
	ros/Makefile	\
	ros/Makefile.nmake	\
	ros/packet-ros-template.c	\
	ros/packet-ros-template.h	\
	ros/ros.asn	\
	ros/Remote-Operations-Generic-ROS-PDUs.asn	\
	ros/Remote-Operations-Information-Objects.asn	\
	ros/Remote-Operations-Useful-Definitions.asn	\
	ros/ros.cnf	\
	ros/ros-exp.cnf	\
	rtse/Makefile	\
	rtse/Makefile.nmake	\
	rtse/packet-rtse-template.c	\
	rtse/packet-rtse-template.h	\
	rtse/rtse.asn	\
	rtse/rtse.cnf	\
	rtse/rtse-exp.cnf	\
	s4406/Makefile	\
	s4406/Makefile.nmake	\
	s4406/packet-s4406-template.c	\
	s4406/packet-s4406-template.h	\
	s4406/s4406.asn	\
	s4406/s4406.cnf	\
	smrse/Makefile	\
	smrse/Makefile.nmake	\
	smrse/packet-smrse-template.c	\
	smrse/packet-smrse-template.h	\
	smrse/SMRSE.asn	\
	smrse/smrse.cnf	\
	snmp/Makefile	\
	snmp/Makefile.nmake	\
	snmp/packet-snmp-template.c	\
	snmp/packet-snmp-template.h	\
	snmp/snmp.asn	\
	snmp/snmp.cnf	\
	snmp/snmp-exp.cnf	\
	spnego/Makefile	\
	spnego/Makefile.nmake	\
	spnego/packet-spnego-template.c	\
	spnego/packet-spnego-template.h	\
	spnego/spnego.asn	\
	spnego/spnego.cnf	\
	tcap/Makefile	\
	tcap/Makefile.nmake	\
	tcap/packet-tcap-template.c	\
	tcap/packet-tcap-template.h	\
	tcap/tcap.asn	\
	tcap/DialoguePDUs.asn	\
	tcap/TCAP-Remote-Operations-Information-Objects.asn	\
	tcap/TCAPMessages.asn	\
	tcap/TCAPPackage.asn	\
	tcap/UnidialoguePDUs.asn	\
	tcap/tcap.cnf	\
	wlancertextn/Makefile	\
	wlancertextn/Makefile.nmake	\
	wlancertextn/packet-wlancertextn-template.c	\
	wlancertextn/packet-wlancertextn-template.h	\
	wlancertextn/WLANCERTEXTN.asn	\
	wlancertextn/wlancertextn.cnf	\
	x411/Makefile	\
	x411/Makefile.nmake	\
	x411/packet-x411-template.c	\
	x411/packet-x411-template.h	\
	x411/x411.asn	\
	x411/x411.cnf	\
	x411/x411-exp.cnf	\
	x420/Makefile	\
	x420/Makefile.nmake	\
	x420/packet-x420-template.c	\
	x420/packet-x420-template.h	\
	x420/x420.asn	\
	x420/ftbp.asn	\
	x420/x420.cnf	\
	x420/x420-exp.cnf	\
	x509af/AuthenticationFramework.asn	\
	x509af/Makefile	\
	x509af/Makefile.nmake	\
	x509af/packet-x509af-template.c	\
	x509af/packet-x509af-template.h	\
	x509af/x509af.cnf	\
	x509af/x509af-exp.cnf	\
	x509ce/CertificateExtensions.asn	\
	x509ce/Makefile	\
	x509ce/Makefile.nmake	\
	x509ce/packet-x509ce-template.c	\
	x509ce/packet-x509ce-template.h	\
	x509ce/x509ce.cnf	\
	x509ce/x509ce-exp.cnf	\
	x509if/InformationFramework.asn	\
	x509if/Makefile	\
	x509if/Makefile.nmake	\
	x509if/packet-x509if-template.c	\
	x509if/packet-x509if-template.h	\
	x509if/x509if.cnf	\
	x509if/x509if-exp.cnf	\
	x509sat/Makefile	\
	x509sat/Makefile.nmake	\
	x509sat/packet-x509sat-template.c	\
	x509sat/packet-x509sat-template.h	\
	x509sat/SelectedAttributeTypes.asn	\
	x509sat/x509sat.cnf	\
	x509sat/x509sat-exp.cnf

MAINTAINERCLEANFILES = \
	Makefile.in

