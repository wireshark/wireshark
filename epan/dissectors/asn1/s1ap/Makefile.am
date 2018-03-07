# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = s1ap

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	S1AP-CommonDataTypes.asn	\
	S1AP-Constants.asn	\
	S1AP-Containers.asn	\
	S1AP-IEs.asn	\
	S1AP-PDU-Contents.asn	\
	S1AP-PDU-Descriptions.asn	\
	S1AP-SonTransfer-IEs.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	packet-$(PROTOCOL_NAME)-template.h \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS =

EXTRA_CNF =
