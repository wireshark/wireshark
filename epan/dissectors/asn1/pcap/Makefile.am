# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = pcap

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	PCAP-CommonDataTypes.asn	\
	PCAP-Constants.asn	\
	PCAP-Containers.asn	\
	PCAP-IEs.asn	\
	PCAP-PDU-Contents.asn	\
	PCAP-PDU-Descriptions.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS =

EXTRA_CNF =
