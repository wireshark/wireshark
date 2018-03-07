# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = rnsap

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	RNSAP-CommonDataTypes.asn	\
	RNSAP-Constants.asn	\
	RNSAP-Containers.asn	\
	RNSAP-IEs.asn	\
	RNSAP-PDU-Contents.asn	\
	RNSAP-PDU-Descriptions.asn

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
